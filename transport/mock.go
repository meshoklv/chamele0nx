package transport

import (
	"context"
	"io"
	"net"
	"time"
)

// MockTransport is a test transport that simulates a working connection.
type MockTransport struct {
	Available   bool
	Latency     time.Duration
	ConnectErr  error
	ProbeErr    error
	ReadData    []byte
	WrittenData []byte
}

// Probe reports the configured availability and latency, or ProbeErr if set.
func (m *MockTransport) Probe(ctx context.Context, endpoint Endpoint) (bool, time.Duration, error) {
	if m.ProbeErr != nil {
		return false, 0, m.ProbeErr
	}
	return m.Available, m.Latency, nil
}

// Connect returns a MockTunnel preloaded with ReadData, or ConnectErr if set.
func (m *MockTransport) Connect(ctx context.Context, endpoint Endpoint) (Tunnel, error) {
	if m.ConnectErr != nil {
		return nil, m.ConnectErr
	}
	return &MockTunnel{
		readData:  m.ReadData,
		transport: m,
	}, nil
}

// Close releases the mock transport. It never fails.
func (m *MockTransport) Close() error {
	return nil
}

// Info returns static metadata describing the mock transport.
func (m *MockTransport) Info() Info {
	return Info{
		Name:           "Mock",
		Type:           "mock",
		Priority:       99,
		MaxBandwidth:   100 * 1024 * 1024, // 100 MB/s
		TypicalLatency: 1 * time.Millisecond,
		SupportsUDP:    true,
	}
}

// MockTunnel simulates a tunnel for testing.
type MockTunnel struct {
	readData  []byte
	readPos   int
	transport *MockTransport
	closed    bool
}

func (t *MockTunnel) Read(p []byte) (n int, err error) {
	if t.readPos >= len(t.readData) {
		return 0, io.EOF
	}
	n = copy(p, t.readData[t.readPos:])
	t.readPos += n
	return n, nil
}

func (t *MockTunnel) Write(p []byte) (n int, err error) {
	t.transport.WrittenData = append(t.transport.WrittenData, p...)
	return len(p), nil
}

// Close marks the mock tunnel as closed. It never fails.
func (t *MockTunnel) Close() error {
	t.closed = true
	return nil
}

// LocalAddr returns a fixed loopback address.
func (t *MockTunnel) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr returns a fixed private-range address.
func (t *MockTunnel) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
}
