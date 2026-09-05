package compat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qlogtest"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

const rustTransferBinEnv = "GO_IROH_RUST_TRANSFER_BIN"
const rustTransferALPN = "n0/iroh/transfer/example/1"
const rustTransferGracefulClose = 1

func TestRustTransferExampleBin(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		t.Setenv(rustTransferBinEnv, "/tmp/rust-transfer")
		t.Setenv(rustRepoEnv, "")
		bin, checked, ok := rustTransferExampleBin()
		if !ok {
			t.Fatal("rustTransferExampleBin ok = false, want true")
		}
		if bin != "/tmp/rust-transfer" {
			t.Fatalf("rustTransferExampleBin bin = %q, want /tmp/rust-transfer", bin)
		}
		if len(checked) != 0 {
			t.Fatalf("rustTransferExampleBin checked = %v, want none", checked)
		}
	})

	t.Run("repo debug", func(t *testing.T) {
		t.Setenv(rustTransferBinEnv, "")
		repo := t.TempDir()
		bin := filepath.Join(repo, "target", "debug", "examples", "transfer")
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(rustRepoEnv, repo)
		got, checked, ok := rustTransferExampleBin()
		if !ok {
			t.Fatal("rustTransferExampleBin ok = false, want true")
		}
		if got != bin {
			t.Fatalf("rustTransferExampleBin bin = %q, want %q", got, bin)
		}
		if len(checked) != 1 || checked[0] != bin {
			t.Fatalf("rustTransferExampleBin checked = %v, want [%q]", checked, bin)
		}
	})

	t.Run("repo release", func(t *testing.T) {
		t.Setenv(rustTransferBinEnv, "")
		repo := t.TempDir()
		debug := filepath.Join(repo, "target", "debug", "examples", "transfer")
		release := filepath.Join(repo, "target", "release", "examples", "transfer")
		if err := os.MkdirAll(filepath.Dir(release), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(release, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(rustRepoEnv, repo)
		got, checked, ok := rustTransferExampleBin()
		if !ok {
			t.Fatal("rustTransferExampleBin ok = false, want true")
		}
		if got != release {
			t.Fatalf("rustTransferExampleBin bin = %q, want %q", got, release)
		}
		if len(checked) != 2 || checked[0] != debug || checked[1] != release {
			t.Fatalf("rustTransferExampleBin checked = %v, want [%q %q]", checked, debug, release)
		}
	})

	t.Run("unset", func(t *testing.T) {
		t.Setenv(rustTransferBinEnv, "")
		t.Setenv(rustRepoEnv, "")
		bin, checked, ok := rustTransferExampleBin()
		if ok {
			t.Fatal("rustTransferExampleBin ok = true, want false")
		}
		if bin != "" || len(checked) != 0 {
			t.Fatalf("rustTransferExampleBin = %q, %v, want empty", bin, checked)
		}
	})
}

func TestParseRustTransferEndpointBoundJSON(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()

	line := fmt.Sprintf(`{"timestamp":"2026-05-31T00:00:00Z","kind":"EndpointBound","endpoint_id":%q,"direct_addresses":["127.0.0.1:1234","[::1]:5678"],"relay_url":"https://relay.example.com/"}`, id.String())
	ready, ok, err := parseRustTransferEndpointBound(line)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("parseRustTransferEndpointBound ok = false, want true")
	}
	if !ready.EndpointID.Equal(id) {
		t.Fatalf("endpoint id = %s, want %s", ready.EndpointID, id)
	}
	if ready.EndpointIDText != id.String() {
		t.Fatalf("endpoint id text = %q, want %q", ready.EndpointIDText, id.String())
	}
	wantAddrs := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1234"),
		netip.MustParseAddrPort("[::1]:5678"),
	}
	if fmt.Sprint(ready.DirectAddrs) != fmt.Sprint(wantAddrs) {
		t.Fatalf("direct addrs = %v, want %v", ready.DirectAddrs, wantAddrs)
	}
	if !ready.HasRelayURL {
		t.Fatal("relay URL missing")
	}
	if ready.RelayURL.String() != "https://relay.example.com/" {
		t.Fatalf("relay URL = %q, want https://relay.example.com/", ready.RelayURL)
	}
	if ready.Line != line {
		t.Fatalf("line = %q, want %q", ready.Line, line)
	}

	_, ok, err = parseRustTransferEndpointBound(`{"timestamp":"2026-05-31T00:00:00Z","kind":"SecretGenerated","secret_key":"abc"}`)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("parseRustTransferEndpointBound ok = true for other event")
	}

	_, ok, err = parseRustTransferEndpointBound(`{"timestamp":"2026-05-31T00:00:00Z","kind":"EndpointArgs","relay_url":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("parseRustTransferEndpointBound ok = true for EndpointArgs")
	}
}

func TestParseRustTransferCompletionJSON(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()

	line := fmt.Sprintf(`{"timestamp":"2026-05-31T00:00:00Z","kind":"DownloadComplete","size":7,"duration":42,"num_chunks":1,"remote_id":%q}`, id.String())
	got, ok, err := parseRustTransferCompletion(line)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("parseRustTransferCompletion ok = false, want true")
	}
	if got.Kind != "DownloadComplete" {
		t.Fatalf("kind = %q, want DownloadComplete", got.Kind)
	}
	if got.Size != 7 {
		t.Fatalf("size = %d, want 7", got.Size)
	}
	if !got.HasRemoteID {
		t.Fatal("remote id missing")
	}
	if !got.RemoteID.Equal(id) {
		t.Fatalf("remote id = %s, want %s", got.RemoteID, id)
	}
	if got.RemoteIDText != id.String() {
		t.Fatalf("remote id text = %q, want %q", got.RemoteIDText, id.String())
	}
	if got.Line != line {
		t.Fatalf("line = %q, want %q", got.Line, line)
	}

	_, ok, err = parseRustTransferCompletion(`not json`)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("parseRustTransferCompletion ok = true for non-json line")
	}

	_, ok, err = parseRustTransferCompletion(`{"timestamp":"2026-05-31T00:00:00Z","kind":"PathStats","paths":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("parseRustTransferCompletion ok = true for PathStats")
	}

	_, ok, err = parseRustTransferCompletion(`{"timestamp":"2026-05-31T00:00:00Z","kind":"UploadComplete","duration":42}`)
	if err == nil {
		t.Fatal("parseRustTransferCompletion missing size err = nil")
	}
	if !ok {
		t.Fatal("parseRustTransferCompletion ok = false for malformed completion")
	}
}

func TestRustTransferUploadRequestBytes(t *testing.T) {
	payload := []byte("go")
	got := rustTransferUploadRequest(payload)
	want := []byte{0, 0, 0, 1, 0x01, 'g', 'o'}
	if !bytes.Equal(got, want) {
		t.Fatalf("rustTransferUploadRequest = %x, want %x", got, want)
	}
}

func TestParseRustTransferCompletionOutput(t *testing.T) {
	output := strings.Join([]string{
		"plain stderr line",
		`{"timestamp":"2026-05-31T00:00:00Z","kind":"ConnectionAccepted","id":0}`,
		`{"timestamp":"2026-05-31T00:00:00Z","kind":"DownloadComplete","size":3,"duration":42,"num_chunks":1}`,
		"",
	}, "\n")
	got, ok, err := findRustTransferCompletion(output, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("findRustTransferCompletion ok = false, want true")
	}
	if got.Kind != "DownloadComplete" || got.Size != 3 {
		t.Fatalf("completion = %+v, want DownloadComplete size 3", got)
	}
}

func TestStartRustTransferProviderReadsEndpointBound(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	line := fmt.Sprintf(`{"timestamp":"2026-05-31T00:00:00Z","kind":"EndpointBound","endpoint_id":%q,"direct_addresses":["127.0.0.1:1234"],"relay_url":"https://relay.example.com/"}`, id.String())

	dir := t.TempDir()
	bin := filepath.Join(dir, "transfer")
	script := fmt.Sprintf(`#!/bin/sh
test "$1" = "--output" || exit 3
test "$2" = "json" || exit 3
test "$3" = "--logs-path" || exit 3
test -d "$4" || exit 3
test "$5" = "provide" || exit 3
test "$6" = "--env" || exit 3
test "$7" = "prod" || exit 3
test -d "$HOME" || exit 3
test -d "$XDG_CONFIG_HOME" || exit 3
test -d "$XDG_CACHE_HOME" || exit 3
test -d "$XDG_DATA_HOME" || exit 3
test -d "$QLOGDIR" || exit 3
trap 'exit 0' INT TERM
printf '%%s\n' '%s'
while :; do sleep 1; done
`, line)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	provider, err := startRustTransferProvider(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Ready.EndpointID.Equal(id) {
		t.Fatalf("endpoint id = %s, want %s", provider.Ready.EndpointID, id)
	}
	if len(provider.Ready.DirectAddrs) != 1 || provider.Ready.DirectAddrs[0] != netip.MustParseAddrPort("127.0.0.1:1234") {
		t.Fatalf("direct addrs = %v, want [127.0.0.1:1234]", provider.Ready.DirectAddrs)
	}
	if !strings.Contains(provider.Output(), line) {
		t.Fatalf("output = %q, want EndpointBound line", provider.Output())
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("stop fake transfer provider: %v\n%s", err, provider.Output())
	}
}

func TestLiveRustTransferGoToRustUpload(t *testing.T) {
	bin := requireRustTransferExample(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	runLiveRustTransferGoToRustUpload(t, ctx, bin, "")
}

func TestLiveRustTransferQlog(t *testing.T) {
	bin := requireRustTransferExample(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	goQlogDir := t.TempDir()
	run := runLiveRustTransferGoToRustUpload(t, ctx, bin, goQlogDir)

	if err := run.Provider.Close(); err != nil {
		t.Fatalf("stop Rust transfer provider: %v\n%s", err, run.Provider.Output())
	}

	qlogCtx, qlogCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer qlogCancel()
	goFiles, err := qlogtest.WaitFiles(qlogCtx, goQlogDir)
	if err != nil {
		t.Fatal(err)
	}
	goFrames, err := qlogtest.FrameTypes(goFiles)
	if err != nil {
		t.Fatal(err)
	}
	if goFrames["max_path_id"] == 0 {
		t.Fatalf("Go qlog frame types = %v, want max_path_id in %v", qlogtest.SortedFrameTypes(goFrames), goFiles)
	}
	if goFrames["add_address"] > 0 {
		t.Logf("Go qlog includes add_address")
	}
	t.Logf("Go qlog files: %v", goFiles)

	rustQlogCtx, rustQlogCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rustQlogCancel()
	rustFiles, err := qlogtest.WaitFiles(rustQlogCtx, run.Provider.QlogDir)
	if err != nil {
		t.Skipf("Rust transfer qlog files not found in %s; build transfer with `cargo +1.94.1 build --locked -p iroh --example transfer --features qlog`: %v", run.Provider.QlogDir, err)
	}
	rustFrames, err := qlogtest.FrameTypes(rustFiles)
	if err != nil {
		t.Fatal(err)
	}
	if rustFrames["max_path_id"] == 0 {
		t.Fatalf("Rust qlog frame types = %v, want max_path_id in %v", qlogtest.SortedFrameTypes(rustFrames), rustFiles)
	}
	t.Logf("Rust qlog files: %v", rustFiles)
}

type rustTransferUploadRun struct {
	Provider *rustTransferProvider
}

func runLiveRustTransferGoToRustUpload(t *testing.T, ctx context.Context, bin, goQlogDir string) rustTransferUploadRun {
	t.Helper()

	provider, err := startRustTransferProvider(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Ready.HasRelayURL {
		t.Fatalf("Rust transfer example EndpointBound has no relay URL\n%s", provider.Output())
	}
	t.Logf("Rust transfer example ready: id=%s direct=%v relay=%s", provider.Ready.EndpointIDText, provider.Ready.DirectAddrs, provider.Ready.RelayURL)

	if goQlogDir != "" {
		t.Setenv("QLOGDIR", goQlogDir)
	}
	client, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeCustomURLs(provider.Ready.RelayURL)))
	if err != nil {
		t.Fatalf("bind Go endpoint: %v", err)
	}
	defer func() {
		if err := client.Shutdown(ctx); err != nil {
			t.Errorf("close Go endpoint: %v", err)
		}
	}()

	if len(provider.Ready.DirectAddrs) == 0 {
		if err := client.Online(ctx); err != nil {
			t.Fatalf("Go endpoint online: %v", err)
		}
	}

	addr := netaddr.NewEndpointAddr(provider.Ready.EndpointID).WithRelayURL(provider.Ready.RelayURL)
	for _, ap := range provider.Ready.DirectAddrs {
		addr = addr.WithIP(ap)
	}

	conn, err := client.Connect(ctx, addr, rustTransferALPN)
	if err != nil {
		t.Fatalf("connect to Rust transfer example: %v\n%s", err, provider.Output())
	}
	connClosed := false
	defer func() {
		if !connClosed {
			_ = conn.CloseWithError(rustTransferGracefulClose, "")
		}
	}()
	if !conn.RemoteID().Equal(provider.Ready.EndpointID) {
		t.Fatalf("remote id = %s, want %s", conn.RemoteID(), provider.Ready.EndpointID)
	}
	if conn.ALPN() != rustTransferALPN {
		t.Fatalf("ALPN = %q, want %q", conn.ALPN(), rustTransferALPN)
	}
	if !conn.MultipathNegotiated() {
		t.Fatalf("MultipathNegotiated = false, want true\n%s", provider.Output())
	}
	t.Logf("Rust transfer connected: id=%s alpn=%q multipath=%t", conn.RemoteID(), conn.ALPN(), conn.MultipathNegotiated())

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := s.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set stream deadline: %v", err)
	}
	payload := []byte("go")
	if _, err := io.Copy(s, bytes.NewReader(rustTransferUploadRequest(payload))); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close stream write side: %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read stream EOF: %v\n%s", err, provider.Output())
	}
	if len(got) != 0 {
		t.Fatalf("stream response = %x, want EOF with no data\n%s", got, provider.Output())
	}

	completion, err := waitRustTransferCompletion(ctx, provider, uint64(len(payload)))
	if err != nil {
		t.Fatalf("wait for Rust transfer completion: %v\n%s", err, provider.Output())
	}
	if completion.Kind != "DownloadComplete" {
		t.Fatalf("completion kind = %q, want DownloadComplete\n%s", completion.Kind, provider.Output())
	}
	if !completion.HasRemoteID {
		t.Fatalf("completion has no remote_id\n%s", provider.Output())
	}
	if !completion.RemoteID.Equal(client.ID()) {
		t.Fatalf("completion remote id = %s, want %s\n%s", completion.RemoteID, client.ID(), provider.Output())
	}

	if err := conn.CloseWithError(rustTransferGracefulClose, ""); err != nil {
		t.Fatalf("close Rust transfer connection: %v\n%s", err, provider.Output())
	}
	connClosed = true
	return rustTransferUploadRun{Provider: provider}
}

func TestLiveRustTransferExampleStarts(t *testing.T) {
	bin := requireRustTransferExample(t)

	provider, err := startRustTransferProvider(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Ready.HasRelayURL {
		t.Fatalf("Rust transfer example EndpointBound has no relay URL\n%s", provider.Output())
	}
	t.Logf("Rust transfer example ready: id=%s direct=%v relay=%s", provider.Ready.EndpointIDText, provider.Ready.DirectAddrs, provider.Ready.RelayURL)
	if err := provider.Close(); err != nil {
		t.Fatalf("stop Rust transfer provider: %v\n%s", err, provider.Output())
	}
}

func requireRustTransferExample(t *testing.T) string {
	t.Helper()
	if os.Getenv(liveRustInteropEnv) != "1" {
		t.Skipf("set %s=1 with %s or %s pointing at a built Rust transfer example; this test never downloads or builds Rust dependencies", liveRustInteropEnv, rustTransferBinEnv, rustRepoEnv)
	}

	bin, checked, ok := rustTransferExampleBin()
	if !ok {
		t.Skipf("%s not set and no local Rust transfer example found via %s; checked %v", rustTransferBinEnv, rustRepoEnv, checked)
	}
	if !filepath.IsAbs(bin) {
		t.Fatalf("%s=%q, want absolute path", rustTransferBinEnv, bin)
	}
	if st, err := os.Stat(bin); err != nil {
		t.Skipf("Rust transfer example %s not found: %v", bin, err)
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("Rust transfer example %s is not executable", bin)
	}
	t.Logf("using Rust transfer example: %s", bin)
	return bin
}

func rustTransferExampleBin() (bin string, checked []string, ok bool) {
	return rustBinFromEnvOrRepo(rustTransferBinEnv,
		filepath.Join("target", "debug", "examples", "transfer"),
		filepath.Join("target", "release", "examples", "transfer"),
	)
}

type rustTransferReady struct {
	EndpointID     key.EndpointID
	EndpointIDText string
	DirectAddrs    []netip.AddrPort
	RelayURL       netaddr.RelayURL
	HasRelayURL    bool
	Line           string
}

func parseRustTransferEndpointBound(line string) (rustTransferReady, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return rustTransferReady{}, false, nil
	}

	var kind struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(line), &kind); err != nil {
		return rustTransferReady{}, false, fmt.Errorf("json: %w", err)
	}
	if kind.Kind != "EndpointBound" {
		return rustTransferReady{}, false, nil
	}

	var event struct {
		EndpointID      string   `json:"endpoint_id"`
		DirectAddresses []string `json:"direct_addresses"`
		RelayURL        *string  `json:"relay_url"`
	}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return rustTransferReady{}, true, fmt.Errorf("EndpointBound json: %w", err)
	}
	if event.EndpointID == "" {
		return rustTransferReady{}, true, fmt.Errorf("missing endpoint_id")
	}

	id, err := parseRustEndpointID(event.EndpointID)
	if err != nil {
		return rustTransferReady{}, true, err
	}
	addrs := make([]netip.AddrPort, 0, len(event.DirectAddresses))
	for _, text := range event.DirectAddresses {
		addr, err := netip.ParseAddrPort(text)
		if err != nil {
			return rustTransferReady{}, true, fmt.Errorf("direct address %q: %w", text, err)
		}
		addrs = append(addrs, addr)
	}
	ready := rustTransferReady{
		EndpointID:     id,
		EndpointIDText: event.EndpointID,
		DirectAddrs:    addrs,
		Line:           line,
	}
	if event.RelayURL != nil {
		if *event.RelayURL == "" {
			return rustTransferReady{}, true, fmt.Errorf("empty relay_url")
		}
		relayURL, err := netaddr.ParseRelayURL(*event.RelayURL)
		if err != nil {
			return rustTransferReady{}, true, fmt.Errorf("relay URL %q: %w", *event.RelayURL, err)
		}
		ready.RelayURL = relayURL
		ready.HasRelayURL = true
	}
	return ready, true, nil
}

type rustTransferCompletion struct {
	Kind         string
	Size         uint64
	RemoteID     key.EndpointID
	RemoteIDText string
	HasRemoteID  bool
	Line         string
}

func parseRustTransferCompletion(line string) (rustTransferCompletion, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return rustTransferCompletion{}, false, nil
	}

	var kind struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(line), &kind); err != nil {
		return rustTransferCompletion{}, false, nil
	}
	if kind.Kind != "DownloadComplete" && kind.Kind != "UploadComplete" {
		return rustTransferCompletion{}, false, nil
	}

	var event struct {
		Size     *uint64 `json:"size"`
		RemoteID *string `json:"remote_id"`
	}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return rustTransferCompletion{}, true, fmt.Errorf("%s json: %w", kind.Kind, err)
	}
	if event.Size == nil {
		return rustTransferCompletion{}, true, fmt.Errorf("%s missing size", kind.Kind)
	}

	completion := rustTransferCompletion{
		Kind: kind.Kind,
		Size: *event.Size,
		Line: line,
	}
	if event.RemoteID != nil {
		if *event.RemoteID == "" {
			return rustTransferCompletion{}, true, fmt.Errorf("%s empty remote_id", kind.Kind)
		}
		id, err := parseRustEndpointID(*event.RemoteID)
		if err != nil {
			return rustTransferCompletion{}, true, err
		}
		completion.RemoteID = id
		completion.RemoteIDText = *event.RemoteID
		completion.HasRemoteID = true
	}
	return completion, true, nil
}

func findRustTransferCompletion(output string, wantSize uint64) (rustTransferCompletion, bool, error) {
	for _, line := range strings.Split(output, "\n") {
		completion, ok, err := parseRustTransferCompletion(line)
		if err != nil {
			return rustTransferCompletion{}, false, err
		}
		if !ok {
			continue
		}
		if completion.Size != wantSize {
			return completion, true, fmt.Errorf("%s size = %d, want %d", completion.Kind, completion.Size, wantSize)
		}
		return completion, true, nil
	}
	return rustTransferCompletion{}, false, nil
}

func waitRustTransferCompletion(ctx context.Context, provider *rustTransferProvider, wantSize uint64) (rustTransferCompletion, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		completion, ok, err := findRustTransferCompletion(provider.Output(), wantSize)
		if err != nil {
			return rustTransferCompletion{}, err
		}
		if ok {
			return completion, nil
		}
		select {
		case <-ctx.Done():
			return rustTransferCompletion{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func rustTransferUploadRequest(payload []byte) []byte {
	request := make([]byte, 0, 5+len(payload))
	request = append(request, 0, 0, 0, 1, 0x01)
	request = append(request, payload...)
	return request
}

type rustTransferProvider struct {
	Ready rustTransferReady

	LogDir  string
	QlogDir string

	cmd     *exec.Cmd
	done    chan error
	out     *rustTransferOutput
	grace   time.Duration
	once    sync.Once
	waitErr error
}

// Close interrupts the provider and waits for it to exit. Exit is an event, so
// the wait is not bounded by a guess at how long a healthy provider takes to
// notice the interrupt: a loaded machine can stretch that from milliseconds to
// seconds. The grace period is only a backstop against a provider that ignores
// the interrupt entirely, and is denominated against the test binary's own
// deadline; after a kill the process is certain to be reaped, so that wait has
// no bound at all.
func (p *rustTransferProvider) Close() error {
	p.once.Do(func() {
		var signalErr error
		if p.cmd.Process != nil {
			if err := p.cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
				signalErr = err
			}
		}
		grace := p.grace
		if grace <= 0 {
			grace = time.Minute
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case err := <-p.done:
			if err != nil {
				p.waitErr = err
			} else if signalErr != nil {
				p.waitErr = fmt.Errorf("%s interrupt: %w", p.cmd.Path, signalErr)
			}
		case <-timer.C:
			if p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
			err := <-p.done
			p.waitErr = fmt.Errorf("%s did not exit within %v of an interrupt; killed it, which reported %v", p.cmd.Path, grace, err)
		}
	})
	return p.waitErr
}

// rustTransferStopGrace reports how long Close may wait for an interrupted
// provider before killing it. It runs until shortly before the test binary
// would time out, so a slow shutdown fails the test only when it is genuinely
// wedged rather than merely descheduled.
func rustTransferStopGrace(t *testing.T) time.Duration {
	deadline, ok := t.Deadline()
	if !ok {
		return time.Minute
	}
	if d := time.Until(deadline) - 30*time.Second; d > time.Second {
		return d
	}
	return time.Second
}

func (p *rustTransferProvider) Output() string {
	return p.out.String()
}

type rustTransferOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *rustTransferOutput) AppendLine(line string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf.WriteString(line)
	o.buf.WriteByte('\n')
}

func (o *rustTransferOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func startRustTransferProvider(t *testing.T, bin string) (*rustTransferProvider, error) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"home", "config", "cache", "data", "logs", "qlog"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			return nil, err
		}
	}
	logDir := filepath.Join(dir, "logs")
	qlogDir := filepath.Join(dir, "qlog")

	cmd := exec.Command(bin,
		"--output", "json",
		"--logs-path", logDir,
		"provide",
		"--env", "prod",
	)
	cmd.Env = append(os.Environ(),
		"HOME="+filepath.Join(dir, "home"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
		"QLOGDIR="+qlogDir,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s stdout: %w", bin, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("%s stderr: %w", bin, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", bin, err)
	}

	out := new(rustTransferOutput)
	lines := make(chan string)
	readyDone := make(chan struct{})
	var scans sync.WaitGroup
	scans.Add(2)
	go scanRustTransferOutput(stdout, out, lines, readyDone, &scans)
	go scanRustTransferOutput(stderr, out, nil, readyDone, &scans)
	scanDone := make(chan struct{})
	go func() {
		scans.Wait()
		close(scanDone)
	}()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	provider := &rustTransferProvider{
		LogDir:  logDir,
		QlogDir: qlogDir,
		cmd:     cmd,
		done:    done,
		out:     out,
		grace:   rustTransferStopGrace(t),
	}

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	defer close(readyDone)
	for {
		select {
		case line := <-lines:
			ready, ok, err := parseRustTransferEndpointBound(line)
			if err != nil {
				_ = provider.Close()
				return nil, fmt.Errorf("%s EndpointBound: %w\n%s", bin, err, out.String())
			}
			if !ok {
				continue
			}
			provider.Ready = ready
			t.Cleanup(func() {
				if err := provider.Close(); err != nil {
					t.Logf("stopping Rust transfer example: %v", err)
				}
			})
			return provider, nil
		case err := <-done:
			waitScan(scanDone)
			if err == nil {
				return nil, fmt.Errorf("%s exited during startup\n%s", bin, out.String())
			}
			return nil, fmt.Errorf("%s exited during startup: %w\n%s", bin, err, out.String())
		case <-timer.C:
			_ = provider.Close()
			return nil, fmt.Errorf("%s did not print EndpointBound within 30s\n%s", bin, out.String())
		}
	}
}

func scanRustTransferOutput(r io.Reader, out *rustTransferOutput, lines chan<- string, done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		out.AppendLine(line)
		if lines == nil {
			continue
		}
		select {
		case lines <- line:
		case <-done:
		}
	}
}
