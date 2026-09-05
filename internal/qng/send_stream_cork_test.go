package quic

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// countingStreamSender records how many times the stream woke the sender.
type countingStreamSender struct {
	sendStreamIrohSender
	mu    sync.Mutex
	wakes int
	ch    chan struct{}
}

func (c *countingStreamSender) onHasStreamData(protocol.StreamID, *SendStream) {
	c.mu.Lock()
	c.wakes++
	c.mu.Unlock()
	select {
	case c.ch <- struct{}{}:
	default:
	}
}

func (c *countingStreamSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wakes
}

func newCorkTestStream() (*SendStream, *countingStreamSender) {
	s := &countingStreamSender{ch: make(chan struct{}, 16)}
	return newSendStream(context.Background(), 0, s, testStreamFC(), false), s
}

// An isolated write must reach the sender immediately. Corking every write
// would add the tail delay to the request half of a ping-pong.
func TestSendStreamIsolatedWriteWakesSenderImmediately(t *testing.T) {
	str, sender := newCorkTestStream()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != 1 {
		t.Fatalf("sender woken %d times, want 1", got)
	}
}

// A stream drained in the middle of a burst is corked: the next write must not
// wake the sender on its own, so the writes behind it can fill a packet.
func TestSendStreamCorksAfterBurstDrain(t *testing.T) {
	str, sender := newCorkTestStream()
	for range sendStreamBurstMinWrites {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	drainOnce(t, str)
	armBurst(str)
	before := sender.count()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != before {
		t.Fatalf("sender woken %d times after the burst drain, want 0: the write was not corked", got-before)
	}
	str.mutex.Lock()
	corked := str.corkPending
	str.mutex.Unlock()
	if !corked {
		t.Fatal("corkPending not set")
	}
}

// A stream drained after only a few writes is not in a burst, so the next
// write is not corked.
func TestSendStreamDoesNotCorkOutsideABurst(t *testing.T) {
	str, sender := newCorkTestStream()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	drainOnce(t, str)
	before := sender.count()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != before+1 {
		t.Fatalf("sender woken %d times, want 1: an isolated write must not be corked", got-before)
	}
}

// The cork is released early once the buffer holds a packet's worth, so the
// tail delay never holds back data that is already ready to send.
func TestSendStreamCorkReleasesAtThreshold(t *testing.T) {
	// Hold off the tail delay, so a wakeup during the loop below can only be
	// the threshold releasing the cork and never the timer expiring. Without
	// this the test is a race between the two under -race.
	defer func(d time.Duration) { sendStreamTailDelay = d }(sendStreamTailDelay)
	sendStreamTailDelay = time.Minute

	str, sender := newCorkTestStream()
	for range sendStreamBurstMinWrites {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	drainOnce(t, str)
	armBurst(str)
	before := sender.count()
	// Writes of 32 bytes each, until the buffer crosses the threshold.
	for i := range sendStreamActivationThreshold/32 + 2 {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if sender.count() > before {
			str.mutex.Lock()
			buffered := str.bufferedWriteLen()
			str.mutex.Unlock()
			if buffered < sendStreamActivationThreshold {
				t.Fatalf("uncorked after write %d with only %d bytes buffered, want >= %d", i, buffered, sendStreamActivationThreshold)
			}
			return
		}
	}
	t.Fatalf("never uncorked after %d bytes buffered", sendStreamActivationThreshold+64)
}

// A corked write must still reach the sender when the tail delay expires;
// otherwise a stream that stops writing mid-burst stalls.
func TestSendStreamCorkTimerWakesSender(t *testing.T) {
	str, sender := newCorkTestStream()
	for range sendStreamBurstMinWrites {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	drainOnce(t, str)
	armBurst(str)
	// Discard wakeups from the burst above, so the receive below can only
	// observe a wakeup caused by the corked write's timer.
	for len(sender.ch) > 0 {
		<-sender.ch
	}
	before := sender.count()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if sender.count() != before {
		t.Fatal("write was not corked, so this test would not exercise the timer")
	}
	select {
	case <-sender.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("cork timer never woke the sender: a stream that stops writing mid-burst would stall")
	}
}

// armBurst puts the stream in the state a burst drain leaves it in, without
// depending on sendStreamBurstFreshness (10us) still being unexpired by the
// time the test gets to its next write.
func armBurst(str *SendStream) {
	str.mutex.Lock()
	str.burstUntil = monotime.Now().Add(time.Minute)
	str.mutex.Unlock()
}

// drainOnce pops frames until the stream reports no more data, which is what
// ends a burst episode.
func drainOnce(t *testing.T, str *SendStream) {
	t.Helper()
	for range 100 {
		_, _, hasMore := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		if !hasMore {
			return
		}
	}
	t.Fatal("stream never drained")
}
