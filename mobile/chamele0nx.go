// Package mobile is a thin gomobile-friendly facade over the Chamele0nX
// transport. It exists to be compiled into Chamele0nX.xcframework via
// `gomobile bind` and consumed from Swift on macOS/iOS (and, eventually,
// Kotlin on Android).
//
// gomobile bind imposes hard limits on the API surface — only a small set
// of types crosses the language boundary safely:
//
//   - signed integers, floats, bool, string
//   - []byte
//   - error
//   - struct types whose exported fields are themselves bind-compatible
//   - interface types whose methods only use bind-compatible types
//
// Crucially, the following do NOT cross: maps, slices of struct,
// channels, context.Context, time.Time, function values. So this package
// hides every Go-only construct (transport.Endpoint with its
// map[string]string Params, the context.Context that drives the reconnect
// loop, the *PersistentClient stats tuple) behind JSON strings and a
// single opaque *Client handle.
//
// The intent is to keep this file small and the wrapped surface
// boring — all the real logic stays in transport/chamele0nx.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/meshoklv/chamele0nx/transport"
	"github.com/meshoklv/chamele0nx/transport/chamele0nx"
)

// Version returns the binding version string. Useful as a smoke test from
// Swift to verify the framework loaded and the symbol table is intact.
func Version() string {
	return "chamele0nx-mobile/0.1.0"
}

// Client is the gomobile-exported handle. Each instance owns one
// PersistentClient — the long-lived reconnecting Chamele0nX tunnel with
// its stable local SOCKS5 listener.
//
// Lifecycle from Swift:
//
//	let c = try MobileNewClient(endpointJSON)
//	let socks = try c.start()       // bind listener, kick off reconnect loop
//	// ... use socks address (e.g. point tun2socks at it) ...
//	try c.stop()                    // graceful shutdown with 5s drain
//
// Start may be called only once per Client. After Stop, create a new Client.
type Client struct {
	mu       sync.Mutex
	pc       *chamele0nx.PersistentClient
	cancelFn context.CancelFunc
	started  bool
	stopped  bool

	// logs captures every slog record produced by the chamele0nx stack
	// while this client is alive. Installed as the global slog default
	// in NewClient — fine for the single-client-per-process model this
	// wrapper supports today.
	logs *logRingBuffer
}

// NewClient parses an endpoint description (JSON shape matches
// transport.Endpoint — id, address, transport, params) and
// returns an unstarted Client.
//
// The endpoint must contain Chamele0nX-required params:
//
//	chameleon_addr  — server host:port
//	user_secret     — user's master secret (HMAC base for auth tokens)
//	server_id       — server identifier (used in token derivation)
//
// Optional params are documented on chamele0nx.Transport. Validation is
// deferred to the first Start call (the same path the CLI uses), so the
// caller doesn't have to duplicate validation logic on the Swift side.
func NewClient(endpointJSON string) (*Client, error) {
	var ep transport.Endpoint
	if err := json.Unmarshal([]byte(endpointJSON), &ep); err != nil {
		return nil, fmt.Errorf("parse endpoint json: %w", err)
	}
	if ep.Transport == "" {
		ep.Transport = "chamele0nx"
	}
	// Install the in-process log buffer BEFORE constructing anything
	// that might log — we want to catch everything from the very first
	// "chamele0nx: connecting tunnel" record onwards.
	logs := installLogBuffer()
	t := chamele0nx.New()
	pc := chamele0nx.NewPersistentClient(t, ep)
	return &Client{pc: pc, logs: logs}, nil
}

// Start binds a local SOCKS5 listener on 127.0.0.1 with a kernel-chosen
// port and starts the background reconnect loop. Returns the bound
// listener address ("127.0.0.1:port") for the caller to point its
// tun2socks (or browser) at.
//
// Returns an error only on synchronous setup failure (port bind, bad
// config). The actual tunnel handshake happens asynchronously — query
// Status() to observe connection state.
func (c *Client) Start() (string, error) {
	return c.startInternal(0)
}

// StartOnPort is like Start but binds the local SOCKS5 listener on the
// specified port instead of letting the kernel choose. Useful when the
// caller has a tun2socks YAML config (e.g. hev-socks5-tunnel on Android)
// that hardcodes the upstream SOCKS port and the listener has to match.
//
// Pass 0 to fall back to kernel-chosen behaviour (equivalent to Start).
func (c *Client) StartOnPort(port int) (string, error) {
	return c.startInternal(port)
}

func (c *Client) startInternal(port int) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return "", errors.New("client has been stopped; create a new one")
	}
	if c.started {
		return "", errors.New("client already started")
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := c.pc.Start(ctx, port); err != nil {
		cancel()
		return "", err
	}
	c.cancelFn = cancel
	c.started = true
	return c.pc.SocksAddr(), nil
}

// Stop performs a graceful shutdown: stops accepting new SOCKS5 clients,
// waits up to 5 seconds for in-flight connections to drain, then closes
// the underlying tunnel and reconnect loop. Idempotent.
//
// Returns context.DeadlineExceeded if drain timed out (existing
// connections were force-closed). All other errors are surfaced from
// PersistentClient.Shutdown.
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return nil
	}
	c.stopped = true

	if !c.started {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.pc.Shutdown(ctx)
	if c.cancelFn != nil {
		c.cancelFn()
	}
	return err
}

// SocksAddr returns the bound listener address, or "" if Start has not
// been called yet. Cheaper than Status() when only the address is needed.
func (c *Client) SocksAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return ""
	}
	return c.pc.SocksAddr()
}

// Status returns a JSON object describing the current Client state:
//
//	{"started": bool, "stopped": bool, "socks_addr": string,
//	 "attempts": uint, "ok": uint, "last_error": string}
//
// `last_error` is the most recent slog record at level ≥ WARN, formatted
// as "HH:MM:SS LEVEL msg k=v...". Empty string when no warning/error
// has been observed yet.
//
// Always returns valid JSON — never errors. Designed to be called
// repeatedly from a Swift menubar/timer to drive UI state.
func (c *Client) Status() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	type statusJSON struct {
		Started   bool   `json:"started"`
		Stopped   bool   `json:"stopped"`
		SocksAddr string `json:"socks_addr"`
		Attempts  uint64 `json:"attempts"`
		OK        uint64 `json:"ok"`
		LastError string `json:"last_error"`
	}
	s := statusJSON{
		Started: c.started,
		Stopped: c.stopped,
	}
	if c.started {
		s.SocksAddr = c.pc.SocksAddr()
		s.Attempts, s.OK = c.pc.Stats()
	}
	if c.logs != nil {
		s.LastError = c.logs.lastErrorOrWarn()
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// RecentLogs returns the in-process log buffer as a single newline-joined
// string, oldest first. Each line is "HH:MM:SS LEVEL msg attrs". Returns
// "" if no logs have been captured yet (NewClient hasn't run).
//
// Used by the iOS smoke test to render Go-side errors that have nowhere
// else to go on a real iPhone — see logbuf.go header for the why.
func (c *Client) RecentLogs() string {
	c.mu.Lock()
	logs := c.logs
	c.mu.Unlock()
	if logs == nil {
		return ""
	}
	return logs.joinAll()
}
