package quic

import (
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
)

var (
	sendStreamBurstFreshness = 10 * time.Microsecond
	sendStreamTailDelay      = 5 * time.Microsecond
)

const (
	sendStreamBurstMinWrites      = 4
	sendStreamActivationThreshold = 1200
)

// activateOrDelayLocked decides whether a write that found the stream inactive
// should wake the sender now. It reports whether the caller must call
// onHasStreamData, which it must do without holding the mutex.
//
// go-iroh addition. Waking the sender on the first write of a burst hands the
// packetizer whatever few bytes have arrived, so a stream written in pieces
// much smaller than a packet sends half-empty packets: the producer never gets
// far enough ahead of the sender to fill one. A stream that has just been
// drained after a burst is therefore corked for sendStreamTailDelay, which
// lets the writes behind the first accumulate, and is uncorked early once the
// buffer holds sendStreamActivationThreshold bytes, roughly a packet's worth,
// so the delay never costs latency on a stream that already has enough to send.
// Only a stream that was drained mid-burst is corked, so an isolated write --
// the request half of a ping-pong -- still wakes the sender immediately.
func (s *SendStream) activateOrDelayLocked() bool {
	if !s.corkPending {
		if s.burstUntil.IsZero() || !monotime.Now().Before(s.burstUntil) {
			s.burstUntil = 0
			s.active = true
			return true
		}
		s.corkPending = true
	}
	if sendStreamTailDelay <= 0 || s.bufferedWriteLen() >= sendStreamActivationThreshold {
		s.stopActivationTimerLocked()
		s.burstUntil = 0
		s.corkPending = false
		s.active = true
		return true
	}
	if s.activationTimer == nil {
		s.activationGen++
		gen := s.activationGen
		s.activationTimer = time.AfterFunc(sendStreamTailDelay, func() {
			s.activateAfterDelay(gen)
		})
	}
	return false
}

// stopActivationTimerLocked cancels a pending cork timer. The generation
// counter makes a timer that has already fired a no-op.
func (s *SendStream) stopActivationTimerLocked() {
	if s.activationTimer == nil {
		return
	}
	s.activationTimer.Stop()
	s.activationTimer = nil
	s.activationGen++
}

// activateAfterDelay wakes the sender for a stream whose cork timer expired.
func (s *SendStream) activateAfterDelay(gen uint64) {
	s.mutex.Lock()
	if gen != s.activationGen {
		s.mutex.Unlock()
		return
	}
	s.activationTimer = nil
	if s.active || s.shutdownErr != nil || s.resetErr != nil ||
		(s.bufferedWriteLen() == 0 && s.dataForWriting == nil) {
		s.mutex.Unlock()
		return
	}
	s.burstUntil = 0
	s.corkPending = false
	s.active = true
	s.mutex.Unlock()
	recordCorkTimerActivation()
	s.sender.onHasStreamData(s.streamID, s)
}

// uncorkLocked drops any pending cork. An event other than an application
// write -- a flow control window opening, a shutdown -- must reach the sender
// without waiting out a tail delay that exists only to batch writes.
func (s *SendStream) uncorkLocked() {
	s.stopActivationTimerLocked()
	s.burstUntil = 0
	s.corkPending = false
}

// noteBufferedWriteLocked counts a write into the current burst episode.
func (s *SendStream) noteBufferedWriteLocked() {
	if s.writesInEpisode < ^uint16(0) {
		s.writesInEpisode++
	}
}

// endEpisodeLocked is called when the sender has drained the stream. A stream
// drained in the middle of a burst is marked fresh, so the next write corks
// rather than waking the sender on its own.
func (s *SendStream) endEpisodeLocked() {
	if s.writesInEpisode >= sendStreamBurstMinWrites {
		s.burstUntil = monotime.Now().Add(sendStreamBurstFreshness)
	} else {
		s.burstUntil = 0
	}
	s.writesInEpisode = 0
	s.corkPending = false
	s.active = false
}
