package iroh

// A server that Close()s an accepted stream without reading the client's
// FIN (and without CancelRead) must still retire it and return MAX_STREAMS
// credit — otherwise a client that opens one short-lived stream per
// operation on a long-lived connection starves at exactly the initial
// stream budget (observed in the field as OpenStreamSync hanging after
// precisely 100 streams on relay-won-then-hole-punched connections).
// streamRounds is deliberately > the initial budget.

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

const streamRounds = 130

// runStreamRounds opens streamRounds sequential streams on conn; each
// writes a few bytes, and closes exactly like a request/response client:
// Close (FIN) then CancelRead. The server side reads the payload but NOT
// the FIN, then Close()s — the field servers' exact shape.
func runStreamRounds(t *testing.T, ctx context.Context, conn *Conn) {
	t.Helper()
	for i := range streamRounds {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		stream, err := conn.OpenStreamConn(sctx)
		cancel()
		if err != nil {
			t.Fatalf("open stream %d: %v (stream credit starvation — streams are not being retired)", i, err)
		}
		if _, err := stream.Write([]byte("ping")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		// Wait for the server's echo byte so the round-trip completed
		// before we close.
		buf := make([]byte, 1)
		_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatalf("read echo %d: %v", i, err)
		}
		_ = stream.Close()
		if cr, ok := stream.(interface{ CancelRead(code uint64) }); ok {
			cr.CancelRead(0)
		}
	}
}

// serveCloseOnly accepts streams, reads the 4-byte payload, echoes one
// byte, and Close()s WITHOUT reading to EOF and WITHOUT CancelRead.
func serveCloseOnly(ctx context.Context, server *Endpoint) {
	for {
		conn, err := server.Accept(ctx)
		if err != nil {
			return
		}
		go func(conn *Conn) {
			for {
				stream, err := conn.AcceptStreamConn(ctx)
				if err != nil {
					return
				}
				go func(s interface {
					io.ReadWriteCloser
				}) {
					buf := make([]byte, 4)
					if _, err := io.ReadFull(s, buf); err == nil {
						_, _ = s.Write([]byte{1})
					}
					_ = s.Close()
				}(stream)
			}
		}(conn)
	}
}

// TestStreamRetirementDirect pins the baseline: on a plain direct
// connection the pattern retires streams and never starves.
func TestStreamRetirementDirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const alpn = "retire-test/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client, err := Bind(ctx, WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	go serveCloseOnly(ctx, server)

	addr := netaddr.NewEndpointAddr(server.ID(), netaddr.IPAddr{Addr: server.LocalAddr()})
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	runStreamRounds(t, ctx, conn)
}

// TestStreamRetirementAfterUpgrade is the field case: relay-won
// connection, hole-punched to a selected direct path, then >100
// sequential streams.
func TestStreamRetirementAfterUpgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	srv := newEchoRelayServer(t)
	relayURL := srv.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const alpn = "retire-test/1"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithRelayMode(mode),
		WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client, err := Bind(ctx,
		WithRelayMode(mode),
		WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	go serveCloseOnly(ctx, server)

	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Wait for the punch to land, as in TestRelayToDirectUpgrade.
	deadline := time.Now().Add(30 * time.Second)
	upgraded := false
	for time.Now().Before(deadline) && !upgraded {
		for _, p := range conn.Paths() {
			if !p.Relayed && p.Selected && p.Validated {
				upgraded = true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !upgraded {
		t.Fatal("premise: connection never migrated to a selected direct path")
	}

	runStreamRounds(t, ctx, conn)
}
