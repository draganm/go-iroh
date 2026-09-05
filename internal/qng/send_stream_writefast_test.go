package quic

import (
	"context"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
)

// The fast path must take the steady-state write, and must refuse every
// condition that makes buffering under the mutex alone unsafe. A condition
// that stops being checked would not fail any other test: the general path
// produces the same result, only slower.
func TestSendStreamWriteFastConditions(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*SendStream)
		p     []byte
		limit func(int) int
		want  bool
	}{
		{name: "steady state", p: make([]byte, 32), want: true},
		{name: "empty write", p: nil, want: false},
		{name: "larger than the buffer", p: make([]byte, maxBufferedWriteSize+1), want: false},
		{name: "limiter", p: make([]byte, 32), limit: func(n int) int { return n }, want: false},
		{
			name:  "sender not yet told",
			setup: func(s *SendStream) { s.active = false },
			p:     make([]byte, 32), want: false,
		},
		{
			name:  "blocking write parked with older bytes",
			setup: func(s *SendStream) { s.dataForWriting = make([]byte, 8) },
			p:     make([]byte, 32), want: false,
		},
		{
			name:  "write limited",
			setup: func(s *SendStream) { s.writeLimited = true },
			p:     make([]byte, 32), want: false,
		},
		{
			name:  "deadline set",
			setup: func(s *SendStream) { s.deadline = monotime.Now() },
			p:     make([]byte, 32), want: false,
		},
		{
			name:  "shut down",
			setup: func(s *SendStream) { s.shutdownErr = &StreamError{} },
			p:     make([]byte, 32), want: false,
		},
		{
			name:  "reset",
			setup: func(s *SendStream) { s.resetErr = &StreamError{} },
			p:     make([]byte, 32), want: false,
		},
		{
			name:  "closed for writing",
			setup: func(s *SendStream) { s.finishedWriting = true },
			p:     make([]byte, 32), want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := newSendStream(context.Background(), 0, sendStreamIrohSender{}, testStreamFC(), false)
			str.active = true // steady state: the sender already knows
			if tt.setup != nil {
				tt.setup(str)
			}
			before := str.bufferedWriteLen()
			if got := str.writeFast(tt.p, tt.limit); got != tt.want {
				t.Fatalf("writeFast = %v, want %v", got, tt.want)
			}
			if got := str.bufferedWriteLen() > before; got != tt.want {
				t.Fatalf("buffered = %v, want %v: the fast path must buffer exactly when it takes the write", got, tt.want)
			}
		})
	}
}

// Data written through the fast path must still arrive, in order.
func TestSendStreamWriteFastDeliversInOrder(t *testing.T) {
	str := newSendStream(context.Background(), 0, sendStreamIrohSender{}, testStreamFC(), false)
	done := drainSendStream(str)
	want := make([]byte, 0, 64*32)
	for i := range 64 {
		p := make([]byte, 32)
		for j := range p {
			p[j] = byte(i)
		}
		if _, err := str.Write(p); err != nil {
			t.Fatal(err)
		}
		want = append(want, p...)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if string(got) != string(want) {
		t.Fatalf("stream delivered %d bytes, want %d", len(got), len(want))
	}
}
