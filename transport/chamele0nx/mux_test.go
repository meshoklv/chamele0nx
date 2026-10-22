package chamele0nx

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// collectWrites returns a writeFn that records every frame it is handed, so a
// test can see what the mux told the peer.
func collectWrites() (func([]byte) error, func() []StreamFrame) {
	var mu sync.Mutex
	var frames []StreamFrame
	write := func(p []byte) error {
		sf, err := DecodeStreamFrame(p)
		if err != nil {
			return err
		}
		mu.Lock()
		frames = append(frames, sf)
		mu.Unlock()
		return nil
	}
	read := func() []StreamFrame {
		mu.Lock()
		defer mu.Unlock()
		out := make([]StreamFrame, len(frames))
		copy(out, frames)
		return out
	}
	return write, read
}

// TestOneStalledStreamDoesNotStopTheTunnel is the regression test for the
// liveness bug that mattered most.
//
// Delivery used to block on a full stream queue, which stopped the dispatcher,
// which stopped the tunnel read loop. Nothing moved after that — not another
// stream, not a FIN, not a close. On the server an idle timeout eventually
// cleared it; on the client nothing did, because the SOCKS5 connection has its
// deadline cleared, so a single application that stopped reading froze every
// other connection through the tunnel for good.
//
// Here one stream is never read from and is flooded well past its queue, while
// a second stream must keep delivering throughout.
func TestOneStalledStreamDoesNotStopTheTunnel(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	stalled := m.AcceptStream(1)
	healthy := m.AcceptStream(2)
	if stalled == nil || healthy == nil {
		t.Fatal("AcceptStream returned nil for the first two streams")
	}

	// Fill the stalled stream past its byte budget and wait until it is
	// genuinely over, so the next frame is the one with nowhere to go.
	// Doing this deterministically matters: with room left, a blocking
	// dispatcher would sail through and the test would pass on broken code.
	chunk := make([]byte, 64<<10)
	for i := 0; i*len(chunk) <= maxStreamBuffer; i++ {
		m.Deliver(StreamFrame{StreamID: 1, Type: streamData, Data: chunk})
	}

	// An unrelated stream must still deliver.
	payload := []byte("still moving")
	m.Deliver(StreamFrame{StreamID: 2, Type: streamData, Data: payload})

	got := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() {
		_, err := healthy.Read(got)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("healthy stream read failed: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("healthy stream got %q, want %q", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled stream blocked an unrelated stream — the tunnel is not independent")
	}
}

// TestStalledStreamIsResetAndAnnounced covers what happens to the stream that
// stopped reading: it is torn down, and the peer is told so it stops sending.
func TestStalledStreamIsResetAndAnnounced(t *testing.T) {
	write, frames := collectWrites()
	m := NewMux(write)
	defer m.Close()

	s := m.AcceptStream(7)
	if s == nil {
		t.Fatal("AcceptStream returned nil")
	}

	// Fill past the byte budget and never read: this is a reader that stopped.
	chunk := make([]byte, 64<<10)
	for i := 0; i*len(chunk) <= maxStreamBuffer; i++ {
		m.Deliver(StreamFrame{StreamID: 7, Type: streamData, Data: chunk})
	}

	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stream whose reader stopped was never reset")
	}

	// The RST is sent from its own goroutine, so give it a moment to land.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hit := false
		for _, f := range frames() {
			if f.StreamID == 7 && f.Type == streamRST {
				hit = true
			}
		}
		if hit {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	var sawRST bool
	for _, f := range frames() {
		if f.StreamID == 7 && f.Type == streamRST {
			sawRST = true
		}
	}
	if !sawRST {
		t.Error("the peer was never told the stream was reset")
	}
	if _, loaded := m.streams.Load(uint32(7)); loaded {
		t.Error("the reset stream is still registered with the mux")
	}
}

// TestStreamLimit pins the cap on concurrent streams. Nothing used to limit
// what an authenticated client could ask for, and every open stream costs a
// goroutine, a socket and a queue on the far side.
func TestStreamLimit(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	for i := 1; i <= maxConcurrentStreams; i++ {
		if s := m.AcceptStream(uint32(i)); s == nil {
			t.Fatalf("AcceptStream refused stream %d, below the limit of %d", i, maxConcurrentStreams)
		}
	}
	if s := m.AcceptStream(uint32(maxConcurrentStreams + 1)); s != nil {
		t.Errorf("AcceptStream accepted stream %d, past the limit", maxConcurrentStreams+1)
	}

	// Closing one makes room again.
	if v, ok := m.streams.Load(uint32(1)); ok {
		_ = v.(*Stream).Close()
	}
	if s := m.AcceptStream(uint32(maxConcurrentStreams + 2)); s == nil {
		t.Error("closing a stream did not free a slot")
	}
}

// TestStreamCountSurvivesRepeatedClose guards the counter itself: a double
// close must not drive it negative, or the limit silently stops applying.
func TestStreamCountSurvivesRepeatedClose(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	s := m.AcceptStream(1)
	if s == nil {
		t.Fatal("AcceptStream returned nil")
	}
	for i := 0; i < 5; i++ {
		_ = s.Close()
		m.removeStream(1)
	}
	if got := m.streamCount.Load(); got != 0 {
		t.Errorf("stream count is %d after repeated closes, want 0", got)
	}
}

// TestAcceptStreamReuseClosesDisplaced covers the leak fixed earlier: a
// repeated CONNECT for an open ID must close the stream it replaces, and must
// not inflate the count.
func TestAcceptStreamReuseClosesDisplaced(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	first := m.AcceptStream(3)
	if first == nil {
		t.Fatal("AcceptStream returned nil")
	}
	second := m.AcceptStream(3)
	if second == nil {
		t.Fatal("AcceptStream returned nil on reuse")
	}
	if first == second {
		t.Fatal("reuse returned the same stream object")
	}

	select {
	case <-first.done:
	case <-time.After(time.Second):
		t.Error("the displaced stream was never closed")
	}
	if got := m.streamCount.Load(); got != 1 {
		t.Errorf("stream count is %d after reusing one ID, want 1", got)
	}
}

// TestDeliverToUnknownStreamIsHarmless: a frame naming a stream that is gone
// must be dropped without disturbing anything else.
func TestDeliverToUnknownStreamIsHarmless(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	m.Deliver(StreamFrame{StreamID: 999, Type: streamData, Data: []byte("orphan")})

	s := m.AcceptStream(1)
	if s == nil {
		t.Fatal("AcceptStream returned nil")
	}
	m.Deliver(StreamFrame{StreamID: 1, Type: streamData, Data: []byte("live")})

	buf := make([]byte, 4)
	if _, err := s.Read(buf); err != nil {
		t.Fatalf("a frame for an unknown stream disturbed a live one: %v", err)
	}
}

// TestResetDoesNotBlockOnATunnelThatIsNotDrained is the regression test for a
// defect introduced by the first version of this mechanism.
//
// Resetting a stalled stream means telling the peer, and telling the peer
// means writing to the tunnel. The first implementation did that inline, on
// the dispatcher goroutine — so when the tunnel write itself blocked, which
// is precisely the situation a stalled stream signals, the dispatcher parked
// and the whole tunnel froze again. The fix moved the RST off the dispatcher.
//
// Here the tunnel write blocks forever. An unrelated stream must still be
// served while a stalled one is being reset.
func TestResetDoesNotBlockOnATunnelThatIsNotDrained(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)

	m := NewMux(func([]byte) error {
		<-blocked // a peer that has stopped reading
		return nil
	})
	defer m.Close()

	stalled := m.AcceptStream(1)
	healthy := m.AcceptStream(2)
	if stalled == nil || healthy == nil {
		t.Fatal("AcceptStream returned nil")
	}

	chunk := make([]byte, 64<<10)
	for i := 0; i*len(chunk) <= maxStreamBuffer; i++ {
		m.Deliver(StreamFrame{StreamID: 1, Type: streamData, Data: chunk})
	}

	payload := []byte("unrelated")
	m.Deliver(StreamFrame{StreamID: 2, Type: streamData, Data: payload})

	got := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() {
		_, err := healthy.Read(got)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unrelated stream read failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resetting a stalled stream blocked the dispatcher on a tunnel write")
	}
}

// TestMuxBufferBudgetIsReleased checks the tunnel-wide accounting: bytes held
// for a stream must come back when that stream goes away, or the budget
// leaks and later streams are reset for no reason.
func TestMuxBufferBudgetIsReleased(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	s := m.AcceptStream(1)
	if s == nil {
		t.Fatal("AcceptStream returned nil")
	}
	data := make([]byte, 32<<10)
	for i := 0; i < 4; i++ {
		m.Deliver(StreamFrame{StreamID: 1, Type: streamData, Data: data})
	}

	deadline := time.Now().Add(2 * time.Second)
	for m.buffered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.buffered.Load() == 0 {
		t.Fatal("delivered bytes were never counted against the tunnel budget")
	}

	_ = s.Close()
	if got := m.buffered.Load(); got != 0 {
		t.Errorf("tunnel budget is %d bytes after the stream closed, want 0", got)
	}
}

// TestReadDrainsQueueAfterClose: data that arrived before the close must
// still be readable, and only then EOF.
func TestReadDrainsQueueAfterClose(t *testing.T) {
	write, _ := collectWrites()
	m := NewMux(write)
	defer m.Close()

	s := m.AcceptStream(1)
	if s == nil {
		t.Fatal("AcceptStream returned nil")
	}
	m.Deliver(StreamFrame{StreamID: 1, Type: streamData, Data: []byte("tail")})

	deadline := time.Now().Add(2 * time.Second)
	for m.buffered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s.closeInternal() // peer sent FIN

	buf := make([]byte, 4)
	n, err := s.Read(buf)
	if err != nil || string(buf[:n]) != "tail" {
		t.Fatalf("Read after close returned (%q, %v), want (\"tail\", nil)", buf[:n], err)
	}
	if _, err := s.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("second Read returned %v, want io.EOF", err)
	}
}
