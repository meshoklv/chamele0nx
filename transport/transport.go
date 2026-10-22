package transport

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// Transport defines the interface for all transport plugins.
// The Chamele0nX transport implements it; the interface exists so an
// alternative one can be dropped in without touching the callers.
type Transport interface {
	// Probe checks if the transport is available for the given endpoint.
	// Returns availability, measured latency, and any error.
	Probe(ctx context.Context, endpoint Endpoint) (available bool, latency time.Duration, err error)

	// Connect establishes a tunnel through the given endpoint.
	Connect(ctx context.Context, endpoint Endpoint) (Tunnel, error)

	// Close shuts down the transport and releases resources.
	Close() error

	// Info returns static metadata about this transport.
	Info() Info
}

// Tunnel represents an established connection through a transport.
type Tunnel interface {
	io.ReadWriteCloser

	// LocalAddr returns the local network address of the tunnel.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address of the tunnel.
	RemoteAddr() net.Addr
}

// Endpoint describes a server endpoint that a transport can connect to.
type Endpoint struct {
	// ID is a unique identifier for this endpoint (used for dedup and tracking).
	ID string `json:"id"`

	// Address is the endpoint in host:port format.
	Address string `json:"address"`

	// Transport names the transport that should handle this endpoint.
	// "chamele0nx" is the only one implemented here.
	Transport string `json:"transport"`

	// Params holds transport-specific configuration. For Chamele0nX these
	// are the chamele0nx_* keys plus user_secret and server_id; they are
	// listed in docs/en/SPEC.md.
	Params map[string]string `json:"params,omitempty"`

	// Priority determines probe order (lower = try first).
	Priority int `json:"priority"`

	// Source indicates which bootstrap channel provided this endpoint.
	Source string `json:"source,omitempty"`

	// UpdatedAt is when this endpoint was last confirmed working.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Info contains static metadata about a transport.
type Info struct {
	// Name is the human-readable transport name.
	Name string

	// Type matches Endpoint.Transport values.
	Type string

	// Priority is the default priority (lower = preferred).
	Priority int

	// MaxBandwidth is the theoretical max throughput in bytes/sec.
	MaxBandwidth int64

	// TypicalLatency is the expected connection latency.
	TypicalLatency time.Duration

	// SupportsUDP indicates whether the transport can carry UDP traffic.
	SupportsUDP bool
}

// Registry holds available transport implementations keyed by type.
// Safe for concurrent use.
type Registry struct {
	mu         sync.RWMutex
	transports map[string]Transport
}

// NewRegistry creates an empty transport registry.
func NewRegistry() *Registry {
	return &Registry{
		transports: make(map[string]Transport),
	}
}

// Register adds a transport implementation for the given type.
func (r *Registry) Register(transportType string, t Transport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transports[transportType] = t
}

// Get returns the transport for the given type, or nil if not registered.
func (r *Registry) Get(transportType string) Transport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.transports[transportType]
}

// All returns a copy of all registered transports.
func (r *Registry) All() map[string]Transport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make(map[string]Transport, len(r.transports))
	for k, v := range r.transports {
		cp[k] = v
	}
	return cp
}
