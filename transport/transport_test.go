package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMockTransportProbe(t *testing.T) {
	mock := &MockTransport{
		Available: true,
		Latency:   50 * time.Millisecond,
	}

	ep := Endpoint{
		ID:        "test-1",
		Address:   "10.0.0.1:443",
		Transport: "mock",
	}

	available, latency, err := mock.Probe(context.Background(), ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available = true")
	}
	if latency != 50*time.Millisecond {
		t.Fatalf("expected latency 50ms, got %v", latency)
	}
}

func TestMockTransportProbeUnavailable(t *testing.T) {
	mock := &MockTransport{
		Available: false,
	}

	ep := Endpoint{ID: "test-2", Address: "10.0.0.2:443", Transport: "mock"}
	available, _, err := mock.Probe(context.Background(), ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available {
		t.Fatal("expected available = false")
	}
}

func TestMockTransportProbeError(t *testing.T) {
	mock := &MockTransport{
		ProbeErr: errors.New("network timeout"),
	}

	ep := Endpoint{ID: "test-3", Address: "10.0.0.3:443", Transport: "mock"}
	_, _, err := mock.Probe(context.Background(), ep)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMockTransportConnect(t *testing.T) {
	mock := &MockTransport{
		Available: true,
		ReadData:  []byte("hello from server"),
	}

	ep := Endpoint{ID: "test-4", Address: "10.0.0.4:443", Transport: "mock"}
	tunnel, err := mock.Connect(context.Background(), ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tunnel.Close()

	// Write data through tunnel
	msg := []byte("hello from client")
	n, err := tunnel.Write(msg)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("expected to write %d bytes, wrote %d", len(msg), n)
	}
	if string(mock.WrittenData) != "hello from client" {
		t.Fatalf("unexpected written data: %s", mock.WrittenData)
	}

	// Read data from tunnel
	buf := make([]byte, 1024)
	n, err = tunnel.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(buf[:n]) != "hello from server" {
		t.Fatalf("unexpected read data: %s", buf[:n])
	}
}

func TestMockTransportConnectError(t *testing.T) {
	mock := &MockTransport{
		ConnectErr: errors.New("connection refused"),
	}

	ep := Endpoint{ID: "test-5", Address: "10.0.0.5:443", Transport: "mock"}
	_, err := mock.Connect(context.Background(), ep)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRegistryBasic(t *testing.T) {
	reg := NewRegistry()

	mock := &MockTransport{Available: true}
	reg.Register("mock", mock)

	got := reg.Get("mock")
	if got == nil {
		t.Fatal("expected registered transport")
	}

	info := got.Info()
	if info.Type != "mock" {
		t.Fatalf("expected type 'mock', got '%s'", info.Type)
	}

	missing := reg.Get("nonexistent")
	if missing != nil {
		t.Fatal("expected nil for unregistered transport")
	}
}

func TestRegistryAll(t *testing.T) {
	reg := NewRegistry()
	reg.Register("a", &MockTransport{})
	reg.Register("b", &MockTransport{})

	all := reg.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 transports, got %d", len(all))
	}
}
