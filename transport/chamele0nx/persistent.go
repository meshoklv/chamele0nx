package chamele0nx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meshoklv/chamele0nx/transport"
)

// PersistentClient maintains a stable local SOCKS5 listener and an
// underlying Chamele0nX tunnel that is automatically re-established on
// failure (network blip, server restart, a DPI box silently dropping
// the flow, and so on).
//
// Lifecycle:
//
//	pc := NewPersistentClient(transport, endpoint)
//	if err := pc.Start(ctx, 0); err != nil { ... }
//	defer pc.Close()
//	addr := pc.SocksAddr() // stable for the lifetime of pc
//
// Reconnect uses exponential backoff (1s → 2s → ... → 60s cap) with
// ±50% jitter so multiple clients cannot reconnect in lockstep
// after a shared disruption. The SOCKS5 listener is created once on Start
// and stays alive across reconnects, so the user-visible socks5://127.0.0.1:port
// address never changes.
//
// Existing SOCKS5 connections are dropped when the underlying tunnel dies
// (the relay loop sees an error). New SOCKS5 connections wait briefly
// (5s) for a new tunnel to come up, otherwise they get a SOCKS5 host
// unreachable response.
type PersistentClient struct {
	transport *Transport
	endpoint  transport.Endpoint

	listener  net.Listener
	socksAddr string

	current atomic.Pointer[Tunnel]

	ctx    context.Context
	cancel context.CancelFunc

	// wg tracks the long-lived background loops (accept, reconnect).
	wg sync.WaitGroup
	// connWg tracks active SOCKS5 client handlers, for graceful drain.
	connWg sync.WaitGroup

	// shuttingDown signals new SOCKS5 connections to drop immediately
	// instead of trying to wait for a tunnel — used during Shutdown.
	shuttingDown atomic.Bool

	closed atomic.Bool

	// connectAttempts is incremented on every reconnect attempt for metrics.
	connectAttempts atomic.Uint64
	// connectsOK is incremented on every successful connect.
	connectsOK atomic.Uint64
}

// NewPersistentClient builds a persistent client. Call Start to bind the
// SOCKS5 listener and begin the reconnect loop.
func NewPersistentClient(t *Transport, endpoint transport.Endpoint) *PersistentClient {
	return &PersistentClient{
		transport: t,
		endpoint:  endpoint,
	}
}

// Start binds a SOCKS5 listener on 127.0.0.1:port (port 0 = random) and
// starts the reconnect loop in the background. Returns once the listener
// is bound; the first tunnel attempt happens asynchronously.
func (pc *PersistentClient) Start(ctx context.Context, port int) error {
	if pc.closed.Load() {
		return errors.New("persistent client already closed")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	pc.listener = ln
	pc.socksAddr = ln.Addr().String()

	pc.ctx, pc.cancel = context.WithCancel(ctx)

	pc.wg.Add(2)
	go pc.acceptLoop()
	go pc.reconnectLoop()

	return nil
}

// SocksAddr returns the stable local SOCKS5 listener address. Safe to
// call after Start.
func (pc *PersistentClient) SocksAddr() string {
	return pc.socksAddr
}

// Stats returns counters for monitoring.
func (pc *PersistentClient) Stats() (attempts, ok uint64) {
	return pc.connectAttempts.Load(), pc.connectsOK.Load()
}

// Close shuts down the persistent client immediately, dropping any active
// SOCKS5 connections and the current tunnel without drain. For graceful
// shutdown that gives existing connections time to finish, use Shutdown.
//
// Safe to call multiple times. Blocks until both background loops have exited.
func (pc *PersistentClient) Close() error {
	if !pc.closed.CompareAndSwap(false, true) {
		return nil
	}

	if pc.cancel != nil {
		pc.cancel()
	}
	if pc.listener != nil {
		// Already-closed is the state Close wants the listener in, so a
		// close error changes nothing about the outcome.
		_ = pc.listener.Close()
	}

	if t := pc.current.Swap(nil); t != nil {
		// Tunnel.Close is documented never to fail; the tunnel is
		// unusable from here regardless.
		_ = t.Close()
	}

	pc.wg.Wait()
	return nil
}

// Shutdown gracefully stops the persistent client:
//
//  1. Stop accepting new SOCKS5 connections (close listener).
//  2. Mark shuttingDown so any in-flight handler that hasn't acquired
//     a tunnel yet drops with "host unreachable".
//  3. Wait for active SOCKS5 handlers to finish, bounded by ctx deadline.
//  4. Close the current tunnel (sends frameClose to server).
//  5. Cancel reconnect loop and wait for background goroutines.
//
// If ctx expires before active connections drain, remaining connections
// are forced shut by tunnel close. Returns nil on clean shutdown,
// ctx.Err() if drain timed out (connections were force-closed).
//
// Safe to call once. Subsequent Shutdown/Close calls are no-ops.
func (pc *PersistentClient) Shutdown(ctx context.Context) error {
	if !pc.closed.CompareAndSwap(false, true) {
		return nil
	}

	pc.shuttingDown.Store(true)

	// Stop accepting new connections.
	if pc.listener != nil {
		// Already-closed is the state Shutdown wants; the drain result
		// below is what the caller acts on.
		_ = pc.listener.Close()
	}

	// Wait for active SOCKS5 handlers to drain, bounded by ctx.
	drainErr := waitWithCtx(ctx, &pc.connWg)

	// Close current tunnel (sends frameClose to server, terminates any
	// surviving connection handlers).
	if t := pc.current.Swap(nil); t != nil {
		// Tunnel.Close never reports failure; drainErr is the value the
		// caller needs.
		_ = t.Close()
	}

	// Cancel reconnect loop and wait for background goroutines.
	if pc.cancel != nil {
		pc.cancel()
	}
	pc.wg.Wait()

	return drainErr
}

// waitWithCtx waits for wg or ctx, whichever fires first. Returns ctx.Err()
// if ctx fired first, nil if wg finished cleanly.
func waitWithCtx(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// reconnectLoop is the heart of persistent connectivity: connect → publish
// → wait for death → backoff → repeat. Exits only when ctx is cancelled.
//
// Backoff strategy depends on error class (see classifyConnectErr):
//   - fatal:    exit reconnect loop entirely (no retry)
//   - auth:     start at 10s, cap at 5min (likely user secret wrong or
//     cover site response — high cost to retry fast, may also
//     be transient if clock skew)
//   - network:  start at 1s, cap at 60s (transient blip, retry quickly)
//   - other:    same as network
func (pc *PersistentClient) reconnectLoop() {
	defer pc.wg.Done()

	const (
		netInitialBackoff  = 1 * time.Second
		netMaxBackoff      = 60 * time.Second
		authInitialBackoff = 10 * time.Second
		authMaxBackoff     = 5 * time.Minute
		// pause between consecutive reconnects to avoid hot loop on flapping
		flapGuard = 500 * time.Millisecond
	)

	backoff := netInitialBackoff
	currentClass := errClassNetwork

	for {
		if pc.ctx.Err() != nil {
			return
		}

		pc.connectAttempts.Add(1)
		slog.Info("chamele0nx: connecting tunnel", "attempt", pc.connectAttempts.Load())

		connectCtx, connectCancel := context.WithTimeout(pc.ctx, 60*time.Second)
		var tun *Tunnel
		var err error
		tun, err = pc.transport.connect(connectCtx, pc.endpoint)
		connectCancel()

		if err != nil {
			class := classifyConnectErr(err)
			if class == errClassFatal {
				// The error text is kept for debug only: a dial failure
				// carries the address it failed to reach, and a client
				// log is often written to disk where that outlives the
				// session. The class is what an operator acts on.
				slog.Error("chamele0nx: fatal connect error, stopping",
					"class", class.String())
				slog.Debug("chamele0nx: fatal connect error detail", "error", err)
				return
			}

			// Reset backoff if class changed (don't carry over network
			// backoff into auth backoff or vice versa).
			if class != currentClass {
				currentClass = class
				if class == errClassAuth {
					backoff = authInitialBackoff
				} else {
					backoff = netInitialBackoff
				}
			}

			// ±50% jitter on the wait, so that N clients which all
			// lost the server at the same second don't all retry at the
			// same second. Only the *wait* is jittered; the exponential
			// growth itself (backoff var) stays deterministic so the cap
			// still bounds worst-case wait.
			waitFor := jitterBackoff(backoff)

			slog.Warn("chamele0nx: connect failed, will retry",
				"class", class.String(),
				"backoff_sec", int(backoff.Seconds()),
				"wait_sec", waitFor.Seconds())
			slog.Debug("chamele0nx: connect failure detail", "error", err)

			if !sleepCtx(pc.ctx, waitFor) {
				return
			}

			maxBackoff := netMaxBackoff
			if class == errClassAuth {
				maxBackoff = authMaxBackoff
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		// Connected successfully — reset backoff and publish.
		backoff = netInitialBackoff
		currentClass = errClassNetwork
		pc.connectsOK.Add(1)
		pc.current.Store(tun)
		slog.Info("chamele0nx: tunnel established", "ok_total", pc.connectsOK.Load())

		// Wait for tunnel death or our shutdown.
		select {
		case <-tun.Done():
			slog.Warn("chamele0nx: tunnel died, will reconnect")
		case <-pc.ctx.Done():
			pc.current.CompareAndSwap(tun, nil)
			// Shutting down; Tunnel.Close never reports failure.
			_ = tun.Close()
			return
		}

		// Tunnel ended naturally — clear pointer and ensure it's fully closed.
		pc.current.CompareAndSwap(tun, nil)
		// Tunnel.Close never reports a failure and the tunnel is already
		// dead; this call just guarantees its resources are released.
		_ = tun.Close()

		// Brief pause before re-attempt to avoid hot reconnect loop on flapping.
		if !sleepCtx(pc.ctx, flapGuard) {
			return
		}
	}
}

// acceptLoop accepts SOCKS5 client connections from the local listener.
// Each accepted connection is dispatched to handleSOCKS5 in its own goroutine
// and tracked in connWg for graceful drain.
func (pc *PersistentClient) acceptLoop() {
	defer pc.wg.Done()

	for {
		conn, err := pc.listener.Accept()
		if err != nil {
			// Listener closed (Close/Shutdown called) → exit cleanly.
			if pc.ctx.Err() != nil || pc.closed.Load() || pc.shuttingDown.Load() {
				return
			}
			// Unexpected error: log and exit. The whole client is stuck if
			// the listener fails — better to surface than silently retry.
			slog.Error("chamele0nx: SOCKS5 accept error, persistent client stopping",
				"error", err)
			return
		}

		// During shutdown the listener is closed, but a connection accepted
		// before that may already be in flight. Drop it cleanly.
		if pc.shuttingDown.Load() {
			// Refusing the connection during shutdown; a close error just
			// means the client already gave up.
			_ = conn.Close()
			continue
		}

		pc.connWg.Add(1)
		go func(c net.Conn) {
			defer pc.connWg.Done()
			pc.handleSOCKS5(c)
		}(conn)
	}
}

// handleSOCKS5 implements RFC 1928 for one client connection.
// Mirrors Tunnel.handleSOCKS5 but waits up to 5s for a tunnel
// to be available before failing — this hides short reconnect blips
// from user-facing applications.
func (pc *PersistentClient) handleSOCKS5(clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	_ = clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Greeting.
	buf := make([]byte, 258)
	n, err := clientConn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}

	// 2. No auth required.
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 3. Request.
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 {
		return
	}
	switch buf[1] {
	case 0x01:
		// CONNECT — handled by the TCP path below.
	case 0x03:
		// UDP ASSOCIATE (0x03) from hev-socks5-tunnel. Relay datagrams
		// through the mux (udp_client.go) so QUIC/DNS work end-to-end.
		// Grab a tunnel now and use its mux for the association lifetime.
		if pc.shuttingDown.Load() {
			_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		tun := pc.waitForTunnel(5 * time.Second)
		if tun == nil {
			_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		handleUDPAssociate(clientConn, tun.Mux())
		return
	default:
		// BIND / unknown. Reply success + bind 0.0.0.0:0 and close so apps
		// fall back to TCP cleanly instead of retry-looping.
		_, _ = clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 4. Parse target.
	var host string
	var port int
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
		port = int(buf[8])<<8 | int(buf[9])
		host = ip.String()
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		host = string(buf[5 : 5+domainLen])
		port = int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
	case 0x04: // IPv6 targets are not carried by the tunnel
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 5. Wait briefly for an active tunnel and open a stream.
	// During shutdown we don't bother waiting — just refuse cleanly.
	if pc.shuttingDown.Load() {
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	tun := pc.waitForTunnel(5 * time.Second)
	if tun == nil {
		// SOCKS5 reply: host unreachable.
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := tun.Mux().OpenStream(host, port)
	if err != nil {
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 6. Success.
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		// The client went away before it could be told the stream is up.
		_ = stream.Close()
		return
	}

	_ = clientConn.SetDeadline(time.Time{})

	// 7. Relay bidirectionally. Same shape as Tunnel.handleSOCKS5.
	done := make(chan struct{}, 2)
	relay := func(dst io.Writer, src io.Reader) {
		buf := make([]byte, 32*1024)
		for {
			nr, err := src.Read(buf)
			if nr > 0 {
				if _, werr := dst.Write(buf[:nr]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}

	go relay(stream, clientConn)
	go relay(clientConn, stream)

	// One direction finished; closing both ends unblocks the other relay
	// goroutine. A close error here only means the peer already hung up.
	<-done
	_ = clientConn.Close()
	_ = stream.Close()
	<-done
}

// waitForTunnel polls for an active tunnel for up to timeout. Returns nil
// if context cancelled or timeout exceeded. Polling interval is short (50ms)
// so user-facing latency is minimal.
//
// Polling is used instead of channel-signaling because tunnel pointer can
// transition multiple times during one wait, and wiring a per-instance
// channel adds bookkeeping overhead. For Phase 1 PoC this is sufficient.
func (pc *PersistentClient) waitForTunnel(timeout time.Duration) *Tunnel {
	deadline := time.Now().Add(timeout)
	for {
		if t := pc.current.Load(); t != nil && !t.IsClosed() {
			return t
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-pc.ctx.Done():
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// --- helpers ---

// nextBackoff doubles backoff up to a cap.
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// jitterBackoff multiplies d by a uniform random factor in [0.5, 1.5).
// Used to break up synchronized reconnect attempts when many clients
// lose the server simultaneously.
//
// Not security-critical — uses math/rand/v2 which is globally seeded
// in Go 1.22+, not crypto/rand.
func jitterBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// Float64() ∈ [0, 1), so 0.5 + Float64() ∈ [0.5, 1.5).
	factor := 0.5 + mathrand.Float64()
	return time.Duration(float64(d) * factor)
}

// sleepCtx sleeps for d or returns false if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// errClass classifies connect errors so reconnect logic can pick a
// reasonable backoff strategy and decide when to give up.
type errClass int

const (
	errClassNetwork errClass = iota // transient: dial, TLS, h2 — quick retry
	errClassAuth                    // server returned cover site or rejected
	errClassFatal                   // config invalid — do not retry
)

func (c errClass) String() string {
	switch c {
	case errClassNetwork:
		return "network"
	case errClassAuth:
		return "auth"
	case errClassFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// classifyConnectErr inspects an error returned from Transport.connect and
// places it into one of three categories that drive backoff strategy:
//
//   - fatal: invalid config, missing params. The user gave us bad input;
//     retrying won't fix anything. Stop the reconnect loop.
//   - auth: server response indicates the auth handshake failed — we got
//     a cover site response or an HTTP error code instead of a tunnel
//     key exchange. Could be a wrong secret (won't fix itself), or
//     transient DPI tampering or clock skew (will fix itself). Either way, slow
//     retry to avoid hammering and giving the wrong impression of an attack.
//   - network: anything else — TCP refused, TLS handshake fail, h2 error,
//     read timeout, etc. Almost always transient on real internet links;
//     retry quickly.
//
// Classification is by error message substring matching. This is
// fragile (refactoring an error message could miscategorize), but Go
// doesn't make it ergonomic to wrap errors with classes through every
// layer (net.Conn → tls.Conn → uTLS → http2.Transport → Chamele0nX).
// For Phase 1 PoC, substring matching is good enough; we'll revisit if
// it causes operational pain.
func classifyConnectErr(err error) errClass {
	if err == nil {
		return errClassNetwork
	}
	msg := err.Error()

	// Fatal: bad config (validateChamele0nXParams).
	if contains(msg, "invalid chamele0nx endpoint") ||
		contains(msg, "missing required param") {
		return errClassFatal
	}

	// Auth: server returned a non-tunnel response. handshake parser
	// produces these specific shapes:
	//   "server returned %d"  ← non-200 status (most likely cover site
	//                            response while we expected tunnel)
	//   "invalid server key exchange frame"  ← we got JSON cover bytes
	//                                          instead of frameKeyExchange
	//   "read server pubkey:" ← read failed mid-handshake (could be
	//                            cover site closing the body early)
	if contains(msg, "server returned ") ||
		contains(msg, "invalid server key exchange") ||
		contains(msg, "read server pubkey") {
		return errClassAuth
	}

	// Everything else: treat as transient network/TLS/h2 issue.
	return errClassNetwork
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
