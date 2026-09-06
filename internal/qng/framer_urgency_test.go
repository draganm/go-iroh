package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// schedStream is a stream that hands out a fixed number of small frames,
// enough for the framer to schedule it.
type schedStream struct {
	id          protocol.StreamID
	urgency     int8
	incremental bool
	generation  uint32
	remaining   int
	retransmits int
}

func (s *schedStream) priority() (int8, bool, uint32) { return s.urgency, s.incremental, s.generation }

func (s *schedStream) frame() ackhandler.StreamFrame {
	f := wire.GetStreamFrame()
	f.StreamID = s.id
	f.Data = f.Data[:4]
	f.DataLenPresent = true
	return ackhandler.StreamFrame{Frame: f}
}

func (s *schedStream) popStreamFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	if s.remaining == 0 {
		return ackhandler.StreamFrame{}, nil, false
	}
	s.remaining--
	return s.frame(), nil, s.remaining > 0
}

func (s *schedStream) popRetransmissionFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, bool) {
	if s.retransmits == 0 {
		return ackhandler.StreamFrame{}, false
	}
	s.retransmits--
	return s.frame(), s.retransmits > 0
}

func newTestFramer() *framer {
	const window = protocol.ByteCount(1) << 40
	cfc := newConnectionFlowController(window, window, nil, utils.NewRTTStats(), utils.DefaultLogger)
	cfc.UpdateSendWindow(window)
	return newFramer(cfc)
}

// drainFramer calls Append until it stops producing STREAM frames, and reports
// how many frames each stream contributed.
func drainFramer(t *testing.T, f *framer) map[protocol.StreamID]int {
	t.Helper()
	got := make(map[protocol.StreamID]int)
	for range 200 {
		_, single, hasSingle, streamFrames, _ := f.Append(nil, nil, 1000, monotime.Now(), protocol.Version1)
		n := 0
		if hasSingle {
			got[single.Frame.StreamID]++
			n++
		}
		for _, sf := range streamFrames {
			got[sf.Frame.StreamID]++
			n++
		}
		if n == 0 {
			break
		}
	}
	return got
}

// Every queued stream must be served regardless of its urgency level. The
// framer scans only the urgency levels it believes are in use, so a level
// wrongly recorded as empty would strand its streams here.
func TestFramerServesEveryUrgencyLevel(t *testing.T) {
	for _, incremental := range []bool{true, false} {
		name := "non-incremental"
		if incremental {
			name = "incremental"
		}
		t.Run(name, func(t *testing.T) {
			f := newTestFramer()
			want := make(map[protocol.StreamID]int)
			for urgency := range int8(8) {
				id := protocol.StreamID(4 * int(urgency))
				str := &schedStream{id: id, urgency: urgency, incremental: incremental, remaining: 3}
				f.AddActiveStream(id, str)
				want[id] = 3
			}
			got := drainFramer(t, f)
			for id, n := range want {
				if got[id] != n {
					t.Errorf("stream %d sent %d frames, want %d", id, got[id], n)
				}
			}
		})
	}
}

// Retransmissions are queued per urgency level too, and are sent before new
// data. A level dropped from the scan would lose the repair entirely.
func TestFramerServesRetransmissionsAtEveryUrgency(t *testing.T) {
	f := newTestFramer()
	want := make(map[protocol.StreamID]int)
	for urgency := range int8(8) {
		id := protocol.StreamID(4 * int(urgency))
		str := &schedStream{id: id, urgency: urgency, retransmits: 2}
		f.AddStreamWithRetransmission(id, str)
		want[id] = 2
	}
	got := drainFramer(t, f)
	for id, n := range want {
		if got[id] != n {
			t.Errorf("stream %d retransmitted %d frames, want %d", id, got[id], n)
		}
	}
}

// A stream whose urgency changes after it was queued is moved to its new
// level while the framer drains, and must still be served.
func TestFramerServesStreamAfterUrgencyChange(t *testing.T) {
	f := newTestFramer()
	str := &schedStream{id: 4, urgency: 0, retransmits: 3}
	f.AddStreamWithRetransmission(4, str)
	str.urgency = 5
	if got := drainFramer(t, f)[4]; got != 3 {
		t.Errorf("stream sent %d frames after moving to urgency 5, want 3", got)
	}
}

// After a 0-RTT rejection the framer drops every queue, so a level left
// marked in use must not resurrect a discarded stream.
func TestFramerHandle0RTTRejectionDropsEveryUrgencyLevel(t *testing.T) {
	f := newTestFramer()
	for urgency := range int8(8) {
		id := protocol.StreamID(4 * int(urgency))
		f.AddActiveStream(id, &schedStream{id: id, urgency: urgency, remaining: 3})
		f.AddStreamWithRetransmission(id, &schedStream{id: id, urgency: urgency, retransmits: 3})
	}
	f.Handle0RTTRejection()
	if f.HasData() {
		t.Error("framer has data after 0-RTT rejection")
	}
	if got := drainFramer(t, f); len(got) != 0 {
		t.Errorf("framer sent %v after 0-RTT rejection, want nothing", got)
	}
}
