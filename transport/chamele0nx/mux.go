package chamele0nx

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

// Stream multiplexer for the Chamele0nX tunnel.
//
// A single HTTP/2 POST carries multiple logical streams (one per SOCKS5 client).
// Each stream has a unique 32-bit ID. The mux layer wraps/unwraps stream frames
// inside the encrypted tunnel, so the server can maintain persistent TCP connections
// per stream.
//
// Wire format of stream payload (inside frameData after decryption):
//   [stream_id:4][stream_type:1][data:N]
//
// Stream types:
//   0x01 = CONNECT (client→server): [host_len:1][host:N][port:2]
//   0x02 = DATA (bidirectional): raw TCP payload
//   0x03 = FIN (either direction): stream closed, no more data
//   0x04 = RST (either direction): stream reset (error)

const (
	streamConnect uint8 = 0x01
	streamData    uint8 = 0x02
	streamFIN     uint8 = 0x03
	streamRST     uint8 = 0x04

	// UDP-over-tunnel sub-types (see udp_client.go / handleStreamConnectUDP).
	//   0x05 = CONNECT_UDP (client→server): [host_len:1][host:N][port:2] (same as CONNECT)
	//   0x06 = DATAGRAM (bidirectional): one frame == one UDP datagram (boundaries preserved)
	streamConnectUDP uint8 = 0x05
	streamDatagram   uint8 = 0x06

	// streamHeaderSize is the mux header: stream_id(4) + type(1).
	streamHeaderSize = 5
)

// Errors returned by the stream multiplexer.
var (
	// ErrStreamClosed is returned when a stream is used after it has been
	// closed locally, either by Close or by a FIN from the peer.
	ErrStreamClosed = errors.New("chamele0nx: stream closed")
	// ErrStreamReset is returned when the peer aborted the stream with an
	// RST instead of a clean FIN.
	ErrStreamReset = errors.New("chamele0nx: stream reset by peer")
	// ErrMuxClosed is returned when the whole multiplexer has been shut
	// down, so no stream on it can carry data any more.
	ErrMuxClosed = errors.New("chamele0nx: mux closed")
	// ErrTooManyStreams is returned when a tunnel already holds
	// maxConcurrentStreams open streams. Every one of them costs a
	// goroutine, a socket and a queue on the far side.
	ErrTooManyStreams = errors.New("chamele0nx: too many concurrent streams")
	// ErrUnknownStream is returned when a frame names a stream ID that is
	// not registered with this multiplexer.
	ErrUnknownStream = errors.New("chamele0nx: unknown stream ID")
)

// StreamFrame is a demuxed stream-level frame.
type StreamFrame struct {
	StreamID uint32
	Type     uint8
	Data     []byte
}

// EncodeStreamFrame encodes a stream frame into a byte slice.
func EncodeStreamFrame(sf StreamFrame) []byte {
	buf := make([]byte, streamHeaderSize+len(sf.Data))
	binary.BigEndian.PutUint32(buf[0:4], sf.StreamID)
	buf[4] = sf.Type
	copy(buf[streamHeaderSize:], sf.Data)
	return buf
}

// DecodeStreamFrame decodes a stream frame from a byte slice.
func DecodeStreamFrame(data []byte) (StreamFrame, error) {
	if len(data) < streamHeaderSize {
		return StreamFrame{}, errors.New("chamele0nx: stream frame too short")
	}
	return StreamFrame{
		StreamID: binary.BigEndian.Uint32(data[0:4]),
		Type:     data[4],
		Data:     data[streamHeaderSize:],
	}, nil
}

// EncodeConnect builds the CONNECT payload: [host_len:1][host:N][port:2].
func EncodeConnect(host string, port int) []byte {
	buf := make([]byte, 1+len(host)+2)
	buf[0] = byte(len(host))
	copy(buf[1:], host)
	binary.BigEndian.PutUint16(buf[1+len(host):], uint16(port))
	return buf
}

// DecodeConnect parses a CONNECT payload.
func DecodeConnect(data []byte) (host string, port int, err error) {
	if len(data) < 4 {
		return "", 0, errors.New("chamele0nx: connect payload too short")
	}
	hostLen := int(data[0])
	if len(data) < 1+hostLen+2 {
		return "", 0, errors.New("chamele0nx: connect payload truncated")
	}
	host = string(data[1 : 1+hostLen])
	port = int(binary.BigEndian.Uint16(data[1+hostLen:]))
	return host, port, nil
}

// Limits that keep one stream from taking the whole tunnel with it.
//
// The receive path used to be fully blocking: a stream's queue filled, deliver
// blocked on it, the dispatcher stopped, the tunnel's incoming channel filled,
// and the tunnel read loop stopped. At that point nothing moved at all — no
// other stream, no FIN, no close. On the server an idle timeout eventually
// tore it down; on the client nothing did, because the SOCKS5 connection has
// its deadline cleared, so one application that stopped reading froze every
// other connection through the tunnel, indefinitely.
//
// The wire format has no flow control yet (see ROADMAP), so a receiver cannot
// slow a sender down. What it can do is never block: delivery appends to a
// per-stream queue bounded in bytes and returns immediately. A reader that
// stops consuming fills its own budget and only its own stream is reset;
// every other stream keeps moving. The application sees a reset connection,
// which is what a real TCP peer produces, rather than a hang.
const (
	// maxStreamBuffer is how many bytes may wait for one stream's reader.
	// Past it, that stream is reset. It has to be large enough that ordinary
	// TCP back-pressure — a paused download, an application that stopped
	// reading for a moment — never reaches it, and small enough that a
	// misbehaving peer cannot buy much memory.
	maxStreamBuffer = 1 << 20 // 1 MiB

	// maxMuxBuffer bounds the same thing across every stream on one tunnel,
	// so many half-full streams cannot add up to an unbounded total.
	maxMuxBuffer = 32 << 20 // 32 MiB

	// maxConcurrentStreams caps how many streams one tunnel may hold open.
	// Nothing previously limited what an authenticated client could ask for.
	maxConcurrentStreams = 512
)

// Mux multiplexes multiple logical streams over a single encrypted tunnel.
// Thread-safe for concurrent stream operations.
type Mux struct {
	nextID  atomic.Uint32
	streams sync.Map // map[uint32]*Stream
	// streamCount tracks the size of streams, which sync.Map does not report.
	streamCount atomic.Int32
	// buffered is the total bytes queued across every stream on this tunnel.
	buffered atomic.Int64

	// writeFn sends an encrypted frame over the tunnel.
	writeFn func(payload []byte) error
	// incoming delivers frames from the tunnel to the appropriate stream.
	incoming chan StreamFrame
	// closed signals mux shutdown.
	closed atomic.Bool
	done   chan struct{}
}

// NewMux creates a multiplexer. writeFn is called to send encrypted data
// over the tunnel (it should encrypt and write a frameData).
func NewMux(writeFn func(payload []byte) error) *Mux {
	m := &Mux{
		writeFn:  writeFn,
		incoming: make(chan StreamFrame, 256),
		done:     make(chan struct{}),
	}
	go m.dispatchLoop()
	return m
}

// OpenStream creates a new client-side stream and sends CONNECT to the server.
func (m *Mux) OpenStream(host string, port int) (*Stream, error) {
	if m.closed.Load() {
		return nil, ErrMuxClosed
	}

	id := m.nextID.Add(1)
	s := newStream(id, m)
	if !m.addStream(id, s) {
		return nil, ErrTooManyStreams
	}

	// Send CONNECT frame.
	connectPayload := EncodeConnect(host, port)
	sf := StreamFrame{StreamID: id, Type: streamConnect, Data: connectPayload}
	if err := m.writeFn(EncodeStreamFrame(sf)); err != nil {
		m.removeStream(id)
		return nil, err
	}

	return s, nil
}

// OpenStreamUDP creates a new client-side stream and sends CONNECT_UDP to the
// server. Mirrors OpenStream but flags the stream as UDP (streamConnectUDP) so
// the server dials UDP instead of TCP. Datagrams then ride the same mux via
// Stream.WriteDatagram / Stream.ReadDatagram.
func (m *Mux) OpenStreamUDP(host string, port int) (*Stream, error) {
	if m.closed.Load() {
		return nil, ErrMuxClosed
	}

	id := m.nextID.Add(1)
	s := newStream(id, m)
	if !m.addStream(id, s) {
		return nil, ErrTooManyStreams
	}

	connectPayload := EncodeConnect(host, port)
	sf := StreamFrame{StreamID: id, Type: streamConnectUDP, Data: connectPayload}
	if err := m.writeFn(EncodeStreamFrame(sf)); err != nil {
		m.removeStream(id)
		return nil, err
	}

	return s, nil
}

// AcceptStream registers a server-side stream (created by an incoming CONNECT).
//
// A repeated CONNECT for an ID that is already open used to overwrite the
// entry and walk away, leaving the previous stream's relay goroutine and its
// TCP connection with nothing to close them: they lingered until the tunnel's
// idle timeout. An authenticated client could accumulate those by replaying
// one CONNECT, so the displaced stream is now closed before it is replaced,
// which unblocks its reader and lets its relay finish.
func (m *Mux) AcceptStream(id uint32) *Stream {
	s := newStream(id, m)

	// Reusing an ID that is already open replaces that stream rather than
	// adding one, so the count does not move and no limit applies.
	if prev, loaded := m.streams.Load(id); loaded {
		m.streams.Store(id, s)
		prev.(*Stream).closeInternal()
		m.releaseBuffer(prev.(*Stream))
		return s
	}

	// A genuinely new stream must pass the limit BEFORE it is published.
	// Storing first and deleting on failure briefly exposes an over-limit
	// stream, and two racing callers on the same fresh ID would have the
	// loser's cleanup evict the winner's stream.
	if !m.addStream(id, s) {
		return nil
	}
	return s
}

// releaseBuffer returns a closed stream's queued bytes to the tunnel budget
// and drops the frames, so a stream nobody will ever read does not keep them.
func (m *Mux) releaseBuffer(s *Stream) {
	s.mu.Lock()
	freed := s.queued
	s.queue = nil
	s.queued = 0
	s.mu.Unlock()
	if freed > 0 {
		m.buffered.Add(int64(-freed))
	}
}

// addStream registers a stream unless the tunnel is already at its limit.
func (m *Mux) addStream(id uint32, s *Stream) bool {
	if m.streamCount.Add(1) > maxConcurrentStreams {
		m.streamCount.Add(-1)
		return false
	}
	m.streams.Store(id, s)
	return true
}

// removeStream drops a stream and keeps the count honest. Deleting a key that
// is not present must not decrement, or repeated closes drive the count
// negative and the limit stops meaning anything.
func (m *Mux) removeStream(id uint32) {
	if _, loaded := m.streams.LoadAndDelete(id); loaded {
		m.streamCount.Add(-1)
	}
}

// Deliver pushes an incoming stream frame into the mux for dispatch.
// Called by the tunnel reader goroutine after decrypting a frameData.
func (m *Mux) Deliver(sf StreamFrame) {
	if m.closed.Load() {
		return
	}
	select {
	case m.incoming <- sf:
	case <-m.done:
	}
}

// dispatchLoop routes incoming frames to the correct stream.
func (m *Mux) dispatchLoop() {
	for {
		select {
		case sf := <-m.incoming:
			v, ok := m.streams.Load(sf.StreamID)
			if !ok {
				continue // unknown stream, ignore
			}
			s := v.(*Stream)
			s.deliver(sf)
		case <-m.done:
			return
		}
	}
}

// WriteRST sends a bare RST for a stream ID this side will not serve. It is
// used when a CONNECT is refused before any Stream object exists to close.
func (m *Mux) WriteRST(id uint32) error {
	return m.writeFn(EncodeStreamFrame(StreamFrame{StreamID: id, Type: streamRST}))
}

// Close shuts down the mux and all streams.
func (m *Mux) Close() {
	if m.closed.Swap(true) {
		return
	}
	close(m.done)
	m.streams.Range(func(key, value any) bool {
		st := value.(*Stream)
		st.closeInternal()
		m.releaseBuffer(st)
		m.removeStream(key.(uint32))
		return true
	})
}

// Stream is a single logical bidirectional byte stream within the mux.
type Stream struct {
	id     uint32
	mux    *Mux
	closed atomic.Bool
	done   chan struct{}
	doneMu sync.Once // guards the single close of done

	// queue holds frames waiting for the reader, oldest first, with queued
	// counting their bytes. A plain channel cannot express a byte budget,
	// and a frame count is the wrong unit: 256 datagrams and 256 full-size
	// records differ by three orders of magnitude in memory.
	mu     sync.Mutex
	queue  [][]byte
	queued int
	// signal carries one wake-up for a reader parked on an empty queue.
	signal chan struct{}

	readBuf []byte // partial read buffer
	readMu  sync.Mutex
}

func newStream(id uint32, mux *Mux) *Stream {
	return &Stream{
		id:     id,
		mux:    mux,
		signal: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

// Read implements io.Reader. Reads data sent by the remote end of this stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		// Drain the partial frame from a previous short read first.
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}
		if data, ok := s.pop(); ok {
			n := copy(p, data)
			if n < len(data) {
				s.readBuf = append([]byte(nil), data[n:]...)
			}
			return n, nil
		}
		select {
		case <-s.signal:
			// Something arrived; loop round and take it.
		case <-s.done:
			// Anything still queued when the stream closed is drained
			// above on the next pass; an empty queue is the end.
			if _, ok := s.peek(); ok {
				continue
			}
			return 0, io.EOF
		}
	}
}

// pop removes the oldest queued frame, if any, and releases its budget.
func (s *Stream) pop() ([]byte, bool) {
	s.mu.Lock()
	if len(s.queue) == 0 {
		s.mu.Unlock()
		return nil, false
	}
	data := s.queue[0]
	s.queue[0] = nil // let the frame be collected once it is handed over
	s.queue = s.queue[1:]
	s.queued -= len(data)
	more := len(s.queue) > 0
	s.mu.Unlock()

	s.mux.buffered.Add(int64(-len(data)))
	if more {
		// Keep a reader that is draining a backlog from parking on an
		// empty signal channel.
		select {
		case s.signal <- struct{}{}:
		default:
		}
	}
	return data, true
}

// peek reports whether anything is still queued.
func (s *Stream) peek() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return nil, false
	}
	return s.queue[0], true
}

// Write implements io.Writer. Sends data to the remote end of this stream.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}
	sf := StreamFrame{StreamID: s.id, Type: streamData, Data: p}
	if err := s.mux.writeFn(EncodeStreamFrame(sf)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends FIN and closes the stream.
func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	// Send FIN to remote. Best effort: if the underlying tunnel is already
	// gone the peer learns the stream ended from the tunnel teardown, and
	// the local half must be torn down either way.
	sf := StreamFrame{StreamID: s.id, Type: streamFIN}
	_ = s.mux.writeFn(EncodeStreamFrame(sf))
	s.closeInternal()
	s.mux.releaseBuffer(s)
	s.mux.removeStream(s.id)
	return nil
}

// closeInternal closes the done channel exactly once, no matter how many
// goroutines reach it. The stream is torn down from several places at
// once — an explicit Close, an incoming FIN, an incoming RST, the mux
// shutting down — and a select/default guard is not safe against two of
// them arriving together: both can observe the channel still open and
// both call close, which panics. sync.Once is the correct guard.
func (s *Stream) closeInternal() {
	s.doneMu.Do(func() { close(s.done) })
}

// deliver pushes a frame into this stream. It never blocks: it runs on the
// dispatcher goroutine, and every other stream on the tunnel is waiting
// behind it.
func (s *Stream) deliver(sf StreamFrame) {
	switch sf.Type {
	case streamData, streamDatagram:
		if s.closed.Load() {
			return
		}
		s.mu.Lock()
		overStream := s.queued+len(sf.Data) > maxStreamBuffer
		s.mu.Unlock()
		overMux := s.mux.buffered.Load()+int64(len(sf.Data)) > maxMuxBuffer
		if overStream || overMux {
			// This reader has stopped consuming, or the tunnel as a whole is
			// holding more than it should. Give up on this one stream.
			s.resetStalled()
			return
		}

		s.mu.Lock()
		s.queue = append(s.queue, sf.Data)
		s.queued += len(sf.Data)
		s.mu.Unlock()
		s.mux.buffered.Add(int64(len(sf.Data)))

		select {
		case s.signal <- struct{}{}:
		default: // a wake-up is already pending; one is enough
		}
	case streamFIN, streamRST:
		s.closeInternal()
	}
}

// resetStalled tears down a stream whose reader stopped consuming and tells
// the peer, so it stops sending into a queue nobody drains. The application
// sees a reset connection — what a real TCP peer would produce — instead of
// silence.
func (s *Stream) resetStalled() {
	if s.closed.Swap(true) {
		return
	}
	// Tear down locally and return immediately: this runs on the dispatcher.
	s.closeInternal()
	s.mux.releaseBuffer(s)
	s.mux.removeStream(s.id)

	// Telling the peer means writing to the tunnel, and a tunnel write blocks
	// when the peer is not reading — which is a state we may well be in. Doing
	// it inline would park the dispatcher and reproduce the very freeze this
	// mechanism exists to prevent, so it goes to its own goroutine.
	go func() {
		_ = s.mux.writeFn(EncodeStreamFrame(StreamFrame{StreamID: s.id, Type: streamRST}))
	}()
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// WriteDatagram sends one UDP datagram over this stream as a single
// streamDatagram frame. Unlike Write (which is a byte stream), each call
// produces exactly one frame so datagram boundaries are preserved end-to-end.
// It bypasses the byte-stream Write path and goes straight through writeFn.
func (s *Stream) WriteDatagram(p []byte) error {
	if s.closed.Load() {
		return ErrStreamClosed
	}
	sf := StreamFrame{StreamID: s.id, Type: streamDatagram, Data: p}
	return s.mux.writeFn(EncodeStreamFrame(sf))
}

// ReadDatagram returns exactly one datagram payload delivered to this stream
// (one frame == one datagram). It returns io.EOF once the stream is closed and
// no buffered datagram remains. Do not mix ReadDatagram with the byte-stream
// Read on the same stream — a stream is used for one or the other.
func (s *Stream) ReadDatagram() ([]byte, error) {
	for {
		if data, ok := s.pop(); ok {
			return data, nil
		}
		select {
		case <-s.signal:
		case <-s.done:
			// Drain a datagram that raced with the close, if any.
			if data, ok := s.pop(); ok {
				return data, nil
			}
			return nil, io.EOF
		}
	}
}
