package chamele0nx

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meshoklv/chamele0nx/internal/chcrypto"
	"golang.org/x/net/http2"
)

// Bounds on how much unauthenticated work one request may buy. A browser
// sends a handful of cookies and a Chamele0nX client sends exactly one, so
// these are orders of magnitude above legitimate use; they exist only to stop
// a crafted Cookie header from turning into unbounded HMAC work.
const (
	maxCookieParts     = 64
	maxAuthCandidates  = 8
	maxRequestHeaderKB = 64
)

// ServerConfig configures a Chamele0nX server.
type ServerConfig struct {
	// ListenAddr is the address to listen on (e.g., ":443").
	ListenAddr string

	// TLSCert and TLSKey are paths to the TLS certificate and key.
	// Must be a valid Let's Encrypt cert for the cover site domain.
	TLSCert string
	TLSKey  string

	// APIPath is the endpoint for tunnel connections (e.g., "/api/v1/events").
	APIPath string

	// CookieFormat for auth token parsing ("generic", "wordpress", "django").
	CookieFormat string

	// UserSecrets maps server_id to user secrets for authentication.
	// In production, this would be a database lookup.
	UserSecrets map[string][]byte

	// ServerID is this server's identifier for auth token validation.
	ServerID string

	// CoverSiteDir is the directory serving the real cover website.
	// Requests without valid auth tokens serve this site (active probe defense).
	CoverSiteDir string

	// SOCKSAddr is the outbound SOCKS5 or direct exit address.
	// Empty means direct connection to the internet.
	SOCKSAddr string

	// AllowPrivateTargets disables SSRF protection. ONLY for testing.
	AllowPrivateTargets bool

	// Logger for structured logging.
	Logger *slog.Logger

	// Profile defines the target TLS record size distribution for shaping.
	// If nil, DefaultSaaSProfile() is used.
	Profile *SiteProfile

	// IdleTimeout closes streams that have been idle (no data in either
	// direction) for this duration. Default 5 minutes if zero. Prevents
	// FD/memory leaks from forgotten or stuck connections.
	IdleTimeout time.Duration

	// DisableDownstreamShaping is a runtime kill-switch for server-side
	// TLS record shaping. When true, accepted connections are handed to
	// http2.Server directly instead of wrapping them in ShapedConn first.
	//
	// Rationale. Field testing in April 2026 showed that shaping the
	// downstream with DefaultSaaSProfile cut throughput on a test
	// handset from 9.4 Mbps to 0.6–2.3 Mbps, a 4–10x slowdown, over a
	// real mobile link. Root cause: a compound
	// stall from a 50–250 ms time.Sleep inside ShapedConn.maybeBurstPause
	// held under writeMu, blocking every concurrent HTTP/2 stream.
	//
	// The primary fix is DefaultServerDownstreamProfile (profile.go:386)
	// which retunes RecordsPerBurst 15–30 and InterBurstPause 20–80 ms.
	// TestShapedConnProfileThroughput asserts this profile runs ≥4× faster
	// than the SaaS profile in-process. The numbers seen on a real
	// deployment still depend on TCP/TLS behaviour and network RTT,
	// which in-process tests cannot model.
	//
	// This flag is the operator's escape hatch: if the retuned profile
	// still regresses on production hardware, setting DisableDownstreamShaping=true
	// drops server-side shaping entirely and falls back to upstream-only
	// shaping (the client still paces every outbound record). That is a
	// strictly weaker defense — downstream traffic becomes a continuous
	// stream again — but it preserves throughput while the profile is
	// tuned. Flipping the flag requires no recompilation; feed it through
	// the same config reload path as the rest of ServerConfig.
	//
	// Default false (shape downstream using the current profile).
	// Do NOT set true casually — running without server-side shaping is
	// visible to a DPI classifier that watches long sessions.
	DisableDownstreamShaping bool
}

// defaultIdleTimeout is used when ServerConfig.IdleTimeout is unset.
const defaultIdleTimeout = 5 * time.Minute

// Server is the Chamele0nX HTTP/2 handler.
// It serves a real website to unauthenticated visitors and tunnels VPN
// data for authenticated clients through the same HTTP/2 connection.
//
// Logging contract (PII safety):
//
//	On level >= Info:  ONLY operational metadata (counters, lifecycle events,
//	                   error types). No client IPs, no destination hostnames,
//	                   no secrets, no auth tokens, no cookie values.
//	On level Debug:    May log destination host/port for failed dials and
//	                   blocked SSRF attempts. This is target metadata, not
//	                   client identity, and is opt-in via -log-level=debug.
//
// Any new s.logger call that adds a field SHOULD be checked against this
// contract. The audit point is: a hostile reader of production logs (info+)
// must NOT be able to derive who connected, where they went, or any of their
// auth material.
type Server struct {
	config     ServerConfig
	coverSite  http.Handler
	activeTuns sync.WaitGroup
	logger     *slog.Logger

	// listener is set by ListenAndServeTLS so Shutdown can close it.
	listener net.Listener

	// shuttingDown signals the accept loop to exit on next Accept error
	// and tells handleTunnel to stop processing new requests cleanly.
	shuttingDown atomic.Bool

	// acceptedConns tracks live TCP connections so Shutdown can force-close
	// them after the drain deadline expires.
	acceptedConns sync.Map // map[net.Conn]struct{}
}

// NewServer creates a new Chamele0nX server.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var coverSite http.Handler
	if cfg.CoverSiteDir != "" {
		coverSite = newCoverFileServer(cfg.CoverSiteDir)
	} else {
		// Minimal cover: a plausible SaaS-like JSON response. Every value
		// that could be compared across deployments is drawn once, here,
		// from crypto/rand — see newDefaultCover for why a constant would
		// be fatal. A real cover site (CoverSiteDir) is still far better,
		// and the server command warns when one was not configured.
		coverSite = newDefaultCover()
	}

	return &Server{
		config:    cfg,
		coverSite: coverSite,
		logger:    logger,
	}
}

// Handler returns the HTTP handler for this server.
// Attach this to an http.Server or Caddy middleware.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.handleRequest)
}

// shapedConnCtxKey is the request-context key under which the server
// stashes the connection's *ShapedConn. It lets the tunnel handler reach
// the shaper and arm it once the client is authenticated. The value is
// set per connection via http2.ServeConnOpts.Context in ListenAndServeTLS.
type shapedConnCtxKey struct{}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// The API path is where the tunnel lives, as an authenticated POST.
	// Everything else that lands on it — a GET, a POST with no or a bad
	// cookie, an unsupported method — must answer the way the real
	// application behind this cover would: like a protected endpoint, not
	// like a file server and not like a stub that hands data to anyone.
	if r.URL.Path == s.config.APIPath {
		if r.Method == http.MethodPost && s.authenticateClient(r) {
			// Client is authenticated: this connection carries a real
			// tunnel, so switch record shaping on now. Until this point
			// the connection served unshaped, so a probe never sees the
			// shaping envelope without a valid cookie.
			s.armShaping(r)
			s.handleTunnel(w, r)
			return
		}
		s.apiDecoy(w, r)
		return
	}

	// Serve cover website for all other requests.
	s.coverSite.ServeHTTP(w, r)
}

// armShaping switches on record shaping for the connection carrying r, if
// that connection is a ShapedConn (it is not when downstream shaping is
// disabled, or on the HTTP/1.1 cover-site path). No-op otherwise.
func (s *Server) armShaping(r *http.Request) {
	if sc, ok := r.Context().Value(shapedConnCtxKey{}).(*ShapedConn); ok {
		sc.Arm()
	}
}

// apiDecoy answers an unauthenticated or malformed request to the tunnel
// API path the way the real application behind this cover would. It is
// reached from handleRequest for any request on the API path that is not
// an authenticated tunnel POST, and its only other caller is the
// regression test below.
//
// An earlier revision returned 200 with a body of invented "events" to
// any caller. That is the opposite of what a real cookie-authenticated
// endpoint does, and it hands an active prober two clean tells at once:
// data returned to an anonymous caller, and a paging cursor that never
// advances between calls. It also diverged by method — a GET on the same
// path fell through to the file server and returned Go's plain-text 404,
// so one endpoint answered as two different applications.
//
// The endpoint now answers uniformly:
//
//   - GET and POST without valid auth: 401 with a small JSON error body,
//     identical on both methods, no data of any kind.
//   - any other method: 405 with an Allow header naming the methods the
//     endpoint implements, the same answer a framework router gives.
//
// The bodies are deliberately constant. A real API's 401 and 405 bodies
// are constant too, so a fixed length here is faithful, not a tell (only
// the earlier data-bearing 200 needed to vary). The X-Request-Id header
// still varies per call, as a real request-tracing middleware emits it.
func (s *Server) apiDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var rid [8]byte
	_, _ = rand.Read(rid[:])
	w.Header().Set("X-Request-Id", fmt.Sprintf("%x", rid))

	switch r.Method {
	case http.MethodGet, http.MethodPost:
		// Missing or invalid credentials on a protected endpoint.
		status, body := unauthorizedResponse(s.config.CookieFormat, w.Header())
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	default:
		// A method the endpoint does not implement.
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, `{"error":"method_not_allowed","message":"Method not allowed."}`)
	}
}

// unauthorizedResponse returns the refusal that the framework named by the
// cookie format actually produces, and sets any header that goes with it. It
// reports the status and the response body.
//
// The cookie already commits the cover site to a persona: FormatCookie emits a
// WordPress or Django session cookie precisely so the header does not stand
// out. The refusal has to match that persona. An earlier revision answered
// every rejection with a flat 401 carrying Django REST Framework's exact
// wording under a key DRF does not use, so a prober comparing the cookie
// against the refusal saw two different applications.
//
// Note what these do NOT send. RFC 9110 15.5.2 says a 401 carries a
// WWW-Authenticate header, and neither WordPress nor a session-cookie API
// sends one — verified against live wordpress.org and ma.tt, which answer an
// unauthenticated REST request with 401, `application/json; charset=UTF-8`,
// and no such header. Imitation beats specification compliance here: adding
// a header the imitated software does not send is a new tell, not a fix.
func unauthorizedResponse(cookieFormat string, h http.Header) (int, string) {
	switch cookieFormat {
	case "django":
		// Django REST Framework with session authentication answers 403,
		// not 401: SessionAuthentication declares no auth scheme, so DRF
		// has nothing to name and downgrades the status. Body and key are
		// DRF's own.
		return http.StatusForbidden, `{"detail":"Authentication credentials were not provided."}`
	case "wordpress":
		// The WordPress REST API's own reply for a logged-out request,
		// including the charset it states on every response.
		h.Set("Content-Type", "application/json; charset=UTF-8")
		return http.StatusUnauthorized,
			`{"code":"rest_not_logged_in","message":"You are not currently logged in.","data":{"status":401}}`
	default:
		// A generic session-cookie API. No WWW-Authenticate: the client
		// authenticates with a cookie, and naming a Bearer or Basic scheme
		// would contradict the very cookie the request carried.
		return http.StatusUnauthorized, `{"error":"unauthorized","message":"Authentication required."}`
	}
}

// authenticateClient validates the auth token from the request cookie.
//
// ===== constant-time secret iteration =====
//
// An earlier revision returned `true` on the first matching secret inside
// the UserSecrets loop. At beta scale (N≈30 secrets per server) that
// exposed a timing oracle: an attacker repeatedly submitting probe tokens
// could statistically distinguish "no match" (N HMAC ops) from "match at
// position 1" (1 HMAC op) from "match at position N" (N HMAC ops).
// Go's map iteration order is randomized per run, so a single probe
// can't pinpoint a position, but averaged over many probes the signal
// still leaks WHICH bucket matched — an information leak even if the
// secret itself is never revealed.
//
// Fix: always iterate every user secret before returning. Total work is
// O(len(UserSecrets) × HMAC) regardless of whether any secret matches
// and of which one matches. We still short-circuit on an empty cookie
// header and on a cookie that fails to parse — those are not secret-
// dependent paths.
//
// ValidateAuthToken itself uses hmac.Equal (constant-time) internally,
// so the HMAC compare is already safe; the only timing leak was the
// outer loop structure, which this change removes.
func (s *Server) authenticateClient(r *http.Request) bool {
	cookieHeader := r.Header.Get("Cookie")
	if cookieHeader == "" {
		return false
	}

	// Parse cookies to find our auth token.
	//
	// Both loops below are bounded on purpose. The header is attacker-supplied
	// and arrives before any authentication has succeeded, while the inner
	// loop is deliberately non-short-circuiting for timing reasons — so the
	// cost of one unauthenticated request is (candidates x secrets x 2)
	// HMAC-SHA256. Without a bound, a single request carrying a header full of
	// repeated cookie segments buys tens of thousands of digests from anyone
	// who can reach the port, on every one of an HTTP/2 connection's streams.
	// The caps are far above what any real client sends and do not change the
	// constant-time properties: the work done is the same for a wrong token
	// and a right one.
	candidates := 0
	for i, part := range strings.Split(cookieHeader, ";") {
		if i >= maxCookieParts {
			break
		}
		part = strings.TrimSpace(part)
		token := ParseCookie(part, s.config.CookieFormat)
		if token == "" {
			continue
		}
		candidates++
		if candidates > maxAuthCandidates {
			break
		}

		// Check against all known user secrets. Iterate ALL secrets
		// even after a match — do not early-return. See the function
		// doc for why.
		matched := false
		for _, secret := range s.config.UserSecrets {
			if ValidateAuthToken(secret, s.config.ServerID, token) {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// handleTunnel processes an authenticated VPN tunnel request.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	s.activeTuns.Add(1)
	defer s.activeTuns.Done()

	// Enable streaming response (HTTP/2 DATA frames sent as they're written).
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.logger.Error("ResponseWriter does not support Flusher")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Read client's ECDH public key.
	clientFrame, err := ReadFrame(r.Body)
	if err != nil {
		s.logger.Error("read client pubkey", "error", err)
		return
	}
	if clientFrame.Type != frameKeyExchange || len(clientFrame.Payload) != 32 {
		s.logger.Error("invalid key exchange frame", "type", clientFrame.Type, "len", len(clientFrame.Payload))
		return
	}

	clientPubKey, err := ecdh.X25519().NewPublicKey(clientFrame.Payload)
	if err != nil {
		s.logger.Error("parse client pubkey", "error", err)
		return
	}

	// Generate server ECDH keypair.
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		s.logger.Error("ecdh keygen", "error", err)
		return
	}

	// Send server's public key to client. The write is padded to a
	// random size so the key-exchange record is not a fixed constant on
	// the wire — see writeKeyExchangeFrame.
	if err := writeKeyExchangeFrame(w, privKey.PublicKey().Bytes()); err != nil {
		s.logger.Error("send server pubkey", "error", err)
		return
	}
	flusher.Flush()

	// Derive shared secret and session key.
	sharedSecret, err := privKey.ECDH(clientPubKey)
	if err != nil {
		s.logger.Error("ecdh", "error", err)
		return
	}
	sessionKey, err := deriveSessionKey(sharedSecret)
	chcrypto.Zeroize(sharedSecret)
	if err != nil {
		s.logger.Error("derive session key", "error", err)
		return
	}
	keyGuard := newSessionKeyGuard(sessionKey)
	defer keyGuard.destroy()

	s.logger.Info("tunnel established")

	// Set up mux-based streaming relay.
	//
	// An http.ResponseWriter may only be touched while its handler is
	// running. Per-stream goroutines outlive individual writes, so every
	// write goes through writeFrameGuarded, and the handler does not
	// return until any write already in flight has finished. Setting the
	// "handler is done" flag while holding the same mutex is what makes
	// that true: a goroutine inside a write holds the mutex, so the
	// deferred teardown blocks behind it, and a goroutine that arrives
	// afterwards sees the flag and gives up instead of writing into a
	// ResponseWriter that is no longer valid.
	fw := &flushWriter{w: w, f: flusher}
	var writeMu sync.Mutex
	var handlerDone atomic.Bool

	writeFrameGuarded := func(f Frame) error {
		if handlerDone.Load() {
			return errHandlerClosed
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		if handlerDone.Load() {
			return errHandlerClosed
		}
		return WriteFrame(fw, f)
	}

	// writeFn encrypts and sends a stream frame over the tunnel.
	writeFn := func(payload []byte) error {
		if handlerDone.Load() {
			return errHandlerClosed
		}
		ciphertext, err := keyGuard.encrypt(payload)
		if err != nil {
			return err
		}
		return writeFrameGuarded(Frame{Type: frameData, Payload: ciphertext})
	}

	mux := NewMux(writeFn)
	defer func() {
		// Take the write mutex before declaring the handler finished, so
		// this waits for any write already under way.
		writeMu.Lock()
		handlerDone.Store(true)
		writeMu.Unlock()
		mux.Close()
	}()

	s.relayTunnel(r.Context(), r.Body, keyGuard, mux)
}

// rejectStream tells the client that a stream it asked for will not be
// served, so it fails immediately instead of waiting for a reply that never
// comes. Best effort: a tunnel that is already gone conveys the same thing.
func (s *Server) rejectStream(mux *Mux, id uint32) {
	// From its own goroutine: this is called on the tunnel read loop, and a
	// tunnel write blocks when the peer is not reading. Blocking here would
	// stop the server reading anything at all from this client.
	go func() { _ = mux.WriteRST(id) }()
}

// relayTunnel reads encrypted frames from client, decrypts, and dispatches
// to the mux. CONNECT frames open new TCP connections; DATA frames relay bytes.
func (s *Server) relayTunnel(ctx context.Context, reader io.Reader, keyGuard *sessionKeyGuard, mux *Mux) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := ReadFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("tunnel read", "error", err)
			}
			return
		}

		switch frame.Type {
		case frameData:
			plaintext, err := keyGuard.decrypt(frame.Payload)
			if err != nil {
				s.logger.Error("decrypt", "error", err)
				return
			}

			sf, err := DecodeStreamFrame(plaintext)
			if err != nil {
				s.logger.Error("decode stream frame", "error", err)
				continue
			}

			switch sf.Type {
			case streamConnect:
				host, port, err := DecodeConnect(sf.Data)
				if err != nil {
					s.logger.Debug("bad connect", "error", err)
					continue
				}
				// Register stream BEFORE starting goroutine so DATA frames
				// arriving before TCP dial completes are buffered, not dropped.
				stream := mux.AcceptStream(sf.StreamID)
				if stream == nil {
					// At the per-tunnel stream limit. Refuse this one and
					// keep the tunnel; the client sees a reset stream.
					s.logger.Debug("stream limit reached", "stream_id", sf.StreamID)
					s.rejectStream(mux, sf.StreamID)
					continue
				}
				go s.handleStreamConnect(ctx, stream, host, port)

			case streamConnectUDP:
				host, port, err := DecodeConnect(sf.Data)
				if err != nil {
					s.logger.Debug("bad connect-udp", "error", err)
					continue
				}
				// Register BEFORE the goroutine so datagram frames arriving
				// before the UDP dial completes are buffered, not dropped.
				stream := mux.AcceptStream(sf.StreamID)
				if stream == nil {
					s.logger.Debug("stream limit reached", "stream_id", sf.StreamID)
					s.rejectStream(mux, sf.StreamID)
					continue
				}
				go s.handleStreamConnectUDP(ctx, stream, host, port)

			case streamData, streamFIN, streamRST, streamDatagram:
				mux.Deliver(sf)

			default:
				s.logger.Debug("unknown stream type", "type", sf.Type)
			}

		case framePing:
			// Read and ignore, matching the client's read loop. Nothing
			// in the protocol consumes a pong for liveness, so answering
			// one only adds a small fixed-size record to the wire. Ping
			// frames now arrive as key-exchange record padding (see
			// writeKeyExchangeFrame); silently dropping them keeps that
			// padding invisible.

		case frameClose:
			s.logger.Info("tunnel closed by client")
			return

		case frameKeyExchange:
			// Client started a fresh ECDH mid-session — it reconnected
			// on its side (for example after its network path flapped)
			// while we still held the old session and were stuck in
			// relay. Treat as a
			// teardown signal: exit relay, let the outer loop recycle
			// the tunnel so the next join picks up the client's new
			// handshake attempt. Without this, server holds a dead
			// session forever while client spins in ReadFrame waiting
			// for a server pubkey reply that will never come.
			s.logger.Info("tunnel: client sent frameKeyExchange in relay — treating as reset",
				"payload_len", len(frame.Payload))
			return

		default:
			s.logger.Warn("unknown frame type", "type", frame.Type)
		}
	}
}

// handleStreamConnect opens a TCP connection for a stream CONNECT request
// and relays data bidirectionally between the stream and the target.
//
// Idle timeout: if neither direction sees data for IdleTimeout (default 5min),
// the TCP read deadline expires and the relay tears down. This prevents stuck
// or forgotten streams from leaking FDs and memory on the server.
func (s *Server) handleStreamConnect(ctx context.Context, stream *Stream, host string, port int) {
	// SSRF protection (disabled in test mode).
	if !s.config.AllowPrivateTargets {
		if err := validateTargetHost(host); err != nil {
			s.logger.Debug("blocked target", "host", host, "error", err)
			// Stream.Close never reports a failure; it just sends a
			// best-effort FIN and marks the stream dead.
			_ = stream.Close()
			return
		}
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		s.logger.Debug("dial failed", "addr", addr, "error", err)
		_ = stream.Close()
		return
	}

	// Post-dial SSRF check.
	if !s.config.AllowPrivateTargets {
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			if isPrivateIP(tcpAddr.IP) {
				// Rebound to a private address after the dial: drop both
				// ends. Nothing useful can come of a close failure here.
				_ = conn.Close()
				_ = stream.Close()
				return
			}
		}
	}

	idle := s.config.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}

	// Relay: target → stream. Reset TCP read deadline before every Read so
	// idle streams (no data from target) eventually time out.
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idle))
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := stream.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Relay: stream → target. Stream.Read has no deadline API, but if the
	// target side times out (above) it closes conn, which fails the next
	// conn.Write here, which propagates back as a relay error.
	//
	// Tradeoff: a stream that's idle from the *target* side first sees the
	// deadline; a stream that's idle from the *client* side waits for the
	// peer to time out. For Phase 1 PoC this asymmetry is acceptable.
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for one direction, then clean up both. Closing here is what
	// unblocks the other goroutine; a close error only means the peer got
	// there first, which is the normal way a relay ends.
	<-done
	_ = conn.Close()
	_ = stream.Close()
	<-done
}

// defaultUDPIdleTimeout bounds an idle UDP flow inside the tunnel. UDP is
// connectionless, so there is no FIN to tear down a forgotten flow — we rely
// entirely on this idle deadline. It is deliberately much shorter than the
// TCP defaultIdleTimeout (5min): DNS/QUIC flows are short-lived and holding a
// UDP socket + goroutine open for minutes per flow would leak resources fast.
const defaultUDPIdleTimeout = 45 * time.Second

// handleStreamConnectUDP dials a UDP socket for a CONNECT_UDP stream and relays
// datagrams bidirectionally between the mux stream and the target, preserving
// datagram boundaries (one frame == one datagram). It reuses the same SSRF gate
// as handleStreamConnect. Both goroutines are torn down when either side ends.
func (s *Server) handleStreamConnectUDP(ctx context.Context, stream *Stream, host string, port int) {
	// SSRF protection (disabled in test mode) — same gate as TCP CONNECT.
	if !s.config.AllowPrivateTargets {
		if err := validateTargetHost(host); err != nil {
			s.logger.Debug("blocked udp target", "host", host, "error", err)
			_ = stream.Close()
			return
		}
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// DialContext rather than net.Dial so that a cancelled tunnel context
	// aborts name resolution instead of leaving this goroutine parked on
	// the resolver. The resulting socket is not bound to ctx and outlives
	// the dial, exactly as in handleStreamConnect.
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		s.logger.Debug("udp dial failed", "addr", addr, "error", err)
		_ = stream.Close()
		return
	}

	// Post-dial SSRF check catches DNS rebinding to a private IP.
	if !s.config.AllowPrivateTargets {
		if udpAddr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			if isPrivateIP(udpAddr.IP) {
				// Rebound to a private address after the dial: drop both
				// ends and say nothing to the client.
				_ = conn.Close()
				_ = stream.Close()
				return
			}
		}
	}

	done := make(chan struct{}, 2)

	// Relay: target → stream. Reset the read deadline before every Read so an
	// idle flow (no datagrams from target) eventually times out and tears down.
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64*1024)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(defaultUDPIdleTimeout))
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := stream.WriteDatagram(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Relay: stream → target. One datagram per ReadDatagram, one Write each.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			dg, err := stream.ReadDatagram()
			if len(dg) > 0 {
				if _, werr := conn.Write(dg); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Same teardown as the TCP relay: closing both ends unblocks the other
	// goroutine, and a close error only means the peer already hung up.
	<-done
	_ = conn.Close()
	_ = stream.Close()
	<-done
}

// validateTargetHost rejects private/loopback hostnames and IPs.
func validateTargetHost(host string) error {
	ip := net.ParseIP(host)
	if ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("target %s is a private/loopback address", host)
		}
	}
	// Domain names are resolved by DialContext; post-dial check catches DNS rebinding.
	return nil
}

// isPrivateIP checks if an IP is in private, loopback, or link-local ranges.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network *net.IPNet
	}{
		{parseCIDR("10.0.0.0/8")},
		{parseCIDR("172.16.0.0/12")},
		{parseCIDR("192.168.0.0/16")},
		{parseCIDR("127.0.0.0/8")},
		{parseCIDR("169.254.0.0/16")},
		{parseCIDR("::1/128")},
		{parseCIDR("fc00::/7")},
		{parseCIDR("fe80::/10")},
	}
	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDR(s string) *net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return n
}

// errHandlerClosed is returned when something tries to write to the
// tunnel after its HTTP handler has returned. At that point the
// ResponseWriter is no longer valid and writing to it is a data race.
var errHandlerClosed = errors.New("chamele0nx: tunnel handler has returned")

// flushWriter wraps an http.ResponseWriter with auto-flush on Write.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.f.Flush()
	}
	return n, err
}

// defaultCover serves a plausible SaaS-like JSON API response when no real
// cover site was configured. Active probers see a normal API returning
// structured JSON.
//
// Nothing it reports may be a constant shared by every deployment. An earlier
// revision answered /api/v1/health with a hardcoded `"version":"2.1.0"` and an
// uptime of `unix % 86400` — seconds since UTC midnight, therefore the same
// number on every server on earth at any instant, resetting to zero at
// midnight. Together those two values were a zero-false-positive scan
// signature: one request per address, one string comparison, and a censor has
// enumerated every deployment. Both are now drawn per server, at startup, so
// two servers never agree and there is no constant left to match on.
type defaultCover struct {
	version   string
	startedAt time.Time
}

func newDefaultCover() *defaultCover {
	// A version a small SaaS backend could plausibly report. The range is
	// wide enough that it does not identify the software, and it is fixed
	// for this process so repeated probes stay consistent with each other.
	return &defaultCover{
		version:   fmt.Sprintf("%d.%d.%d", 1+randInt(4), randInt(20), randInt(40)),
		startedAt: time.Now().Add(-time.Duration(randInt(90*24*3600)) * time.Second),
	}
}

// randInt returns a uniform value in [0,n) from crypto/rand. n must be
// positive. Failure is not survivable here: a cover value that silently
// degrades to a constant is the very thing this type exists to prevent.
func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("chamele0nx: crypto/rand unavailable: " + err.Error())
	}
	return int(v.Int64())
}

func (d *defaultCover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Random request ID (not sequential timestamp — detectable by active probers).
	var rid [8]byte
	rand.Read(rid[:])
	w.Header().Set("X-Request-Id", fmt.Sprintf("%x", rid))

	switch r.URL.Path {
	case "/api/v1/health":
		w.WriteHeader(http.StatusOK)
		// A write failure here means the prober hung up mid-response.
		// There is no fallback response to send and nothing worth logging.
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":%q,"uptime":%d}`,
			d.version, int64(time.Since(d.startedAt).Seconds()))
	case "/api/v1/events":
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"events":[],"cursor":"","has_more":false}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"error":"not_found","message":"The requested resource was not found"}`)
	}
}

// serveHTTP1 serves one already-handshaked connection as HTTP/1.1 using
// handler, and returns when the connection is done. It exists because the
// listener advertises http/1.1 in ALPN (so an active prober's http/1.1
// handshake succeeds like it would against a real site) while the tunnel
// itself is HTTP/2-only. Traffic here is always the cover site and is
// never shaped.
func (s *Server) serveHTTP1(c net.Conn, handler http.Handler) {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Same ceiling as the HTTP/2 path. This route reaches the same
		// handler, authenticateClient included, so leaving it at Go's 1 MiB
		// default would leave the cookie parsing bounded on one protocol
		// and not the other.
		MaxHeaderBytes: maxRequestHeaderKB << 10,
	}
	// Serve drives one connection and returns once the listener reports
	// it drained, which happens when the connection closes. The error is
	// always that drain sentinel; there is nothing to act on.
	_ = srv.Serve(newSingleConnListener(c))
}

// singleConnListener is a net.Listener that yields exactly one connection
// and then blocks Accept until that connection closes, at which point
// Accept returns net.ErrClosed so http.Server.Serve unwinds. It lets an
// already-accepted net.Conn be driven by the standard net/http server
// without inventing a real listener.
type singleConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	l := &singleConnListener{addr: c.LocalAddr(), done: make(chan struct{})}
	// Wrap so the listener learns the moment http.Server closes the conn.
	l.conn = &closeNotifyConn{Conn: c, notify: l.finish}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.finish()
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }

func (l *singleConnListener) finish() { l.once.Do(func() { close(l.done) }) }

// closeNotifyConn calls notify once, the first time Close is called, so a
// singleConnListener can wake its blocked Accept when the served
// connection is done.
type closeNotifyConn struct {
	net.Conn
	once   sync.Once
	notify func()
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.notify)
	return err
}

// ListenAndServeTLS starts the Chamele0nX server with TLS record shaping.
// Uses http2.Server.ServeConn to wrap each accepted connection with
// ShapedConn for profile-based TLS record size control.
//
// Returns when the listener is closed (e.g. by Shutdown). Returns nil on
// graceful shutdown, or the underlying error if Accept failed for an
// unexpected reason.
func (s *Server) ListenAndServeTLS() error {
	cert, err := tls.LoadX509KeyPair(s.config.TLSCert, s.config.TLSKey)
	if err != nil {
		return fmt.Errorf("load tls keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Offer both h2 and http/1.1. A real site almost always agrees
		// to HTTP/1.1, so advertising h2 alone is a discriminator an
		// active prober settles in a single handshake: it offers only
		// http/1.1 and a real site answers while an h2-only server sends
		// no_application_protocol. h2 stays first, so the tunnel client
		// (which offers both, h2 preferred) still lands on h2; the
		// http/1.1 path only ever carries cover-site traffic.
		NextProtos:                  []string{"h2", "http/1.1"},
		DynamicRecordSizingDisabled: true,
	}

	ln, err := tls.Listen("tcp", s.config.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls listen: %w", err)
	}
	s.listener = ln
	// Shutdown may have closed the listener already, in which case this
	// second close reports ErrClosed; either way the listener is gone.
	defer func() { _ = ln.Close() }()

	// The server default is DefaultServerDownstreamProfile, not SaaS.
	// The SaaS profile's 50–250ms burst pauses and 5–15 records/burst
	// were measured in April 2026 to cap downstream throughput at about
	// 1 Mbps under symmetric shaping — that deployment took a test
	// handset from 9.4 Mbps down to 0.6–2.3 Mbps and had to be rolled
	// back. The
	// downstream profile has 15–30 records/burst, 20–80ms pauses, and
	// larger record-size bias, matching how a real SaaS backend
	// dispatches batched JSON/asset responses. See
	// TestShapedConnProfileThroughput for the numeric guard.
	//
	// Operators who explicitly wire config.Profile in ServerConfig still
	// get their exact choice — this fallback only kicks in when no
	// profile was set at all.
	profile := s.config.Profile
	if profile == nil {
		profile = DefaultServerDownstreamProfile()
	}

	h2s := &http2.Server{
		IdleTimeout: 120 * time.Second,
	}
	// http2 takes its header-list ceiling from the base http.Server, and
	// falls back to http.DefaultMaxHeaderBytes (1 MiB) when there is none.
	// A real browser never approaches 64 KiB of headers, and the smaller
	// ceiling is what bounds the cookie parsing in authenticateClient.
	h2Base := &http.Server{MaxHeaderBytes: maxRequestHeaderKB << 10}
	handler := s.Handler()

	s.logger.Info("chamele0nx server starting",
		"addr", s.config.ListenAddr,
		"api_path", s.config.APIPath,
		"server_id", s.config.ServerID,
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed by Shutdown → graceful exit, not an error.
			if s.shuttingDown.Load() {
				return nil
			}
			return err
		}

		// Track accepted connection so Shutdown can force-close it after
		// the drain deadline expires.
		s.acceptedConns.Store(conn, struct{}{})

		// Handshake in a per-connection goroutine to avoid
		// blocking the accept loop (slowloris defense).
		go func(c net.Conn) {
			defer s.acceptedConns.Delete(c)

			// TLS handshake must complete before http2.ServeConn
			// reads ConnectionState() — lazy handshake returns Version=0
			// which http2 rejects as INADEQUATE_SECURITY. It also tells
			// us the negotiated ALPN so we can pick the right server.
			tlsConn, isTLS := c.(*tls.Conn)
			if isTLS {
				// A deadline can only fail to set on an already-closed
				// connection, which the Handshake below then reports.
				_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					_ = c.Close()
					return
				}
				_ = tlsConn.SetDeadline(time.Time{}) // clear deadline
			}

			// A peer that negotiated HTTP/1.1 gets the cover site over a
			// plain HTTP/1.1 server. The tunnel is HTTP/2-only, so this
			// path never carries tunnel traffic and is never shaped —
			// it exists purely so the server answers http/1.1 the way a
			// real site would instead of refusing the protocol.
			if isTLS && tlsConn.ConnectionState().NegotiatedProtocol == "http/1.1" {
				s.serveHTTP1(c, handler)
				_ = c.Close()
				return
			}

			// HTTP/2 path. Per-connection profile personalization: each
			// accepted client sees a slightly different "real site" so
			// concurrent Chamele0nX users on the wire don't share an
			// identical envelope. seed=0 short-circuits to no jitter, so
			// this is safe even if generateClientSeed somehow returns 0.
			//
			// Shaping starts un-armed and is switched on by the tunnel
			// handler once the client authenticates (handleRequest ->
			// armShaping), so an unauthenticated probe never sees the
			// shaped envelope. The connection's ShapedConn is threaded
			// to the handler via the ServeConn base context.
			//
			// Kill-switch: if DisableDownstreamShaping is set, skip the
			// ShapedConn wrapper entirely and serve the raw TLS conn. See
			// the ServerConfig field doc for when this is an acceptable
			// operational choice.
			served := c
			opts := &http2.ServeConnOpts{Handler: handler, BaseConfig: h2Base}
			if !s.config.DisableDownstreamShaping {
				seed := generateClientSeed()
				sc := newGatedShapedConn(c, profile.PersonalizeFor(seed), seed)
				served = sc
				opts.Context = context.WithValue(context.Background(), shapedConnCtxKey{}, sc)
			}
			h2s.ServeConn(served, opts)
			// ServeConn has returned, so this connection is finished; a
			// close error only means the peer got there first.
			_ = c.Close()
		}(conn)
	}
}

// Shutdown gracefully stops the Chamele0nX server:
//
//  1. Closes the TLS listener so no new connections are accepted.
//  2. Waits for active tunnel handlers (handleTunnel) to drain, bounded
//     by ctx deadline.
//  3. After deadline (or on success), force-closes any remaining accepted
//     TCP connections to terminate stuck handlers.
//
// Returns nil on clean drain, or ctx.Err() if drain timed out.
// Safe to call once. Concurrent calls are not supported (caller must
// coordinate with signal handler).
func (s *Server) Shutdown(ctx context.Context) error {
	if !s.shuttingDown.CompareAndSwap(false, true) {
		return nil
	}

	// Stop accepting new connections on the TLS listener (the HTTP/2
	// POST path) and on any optional UDP-based cover ingress. All paths
	// share the same activeTuns WaitGroup, so the single waitWGCtx call
	// below drains them together.
	if s.listener != nil {
		// Best effort: a listener that is already closed is exactly the
		// state Shutdown wants it in.
		_ = s.listener.Close()
	}

	// Wait for active tunnels to finish, bounded by ctx.
	drainErr := waitWGCtx(ctx, &s.activeTuns)

	// After drain (success or timeout), force-close any surviving accepted
	// connections. On clean drain this is a no-op; on timeout it terminates
	// stuck handlers so they don't leak.
	s.acceptedConns.Range(func(key, _ any) bool {
		if c, ok := key.(net.Conn); ok {
			// Force-closing a stuck handler's connection; if it is already
			// closed, the goal is met anyway.
			_ = c.Close()
		}
		s.acceptedConns.Delete(key)
		return true
	})

	return drainErr
}

// waitWGCtx waits for wg.Wait() or ctx, whichever fires first.
// Returns nil on clean wg completion, ctx.Err() on timeout.
func waitWGCtx(ctx context.Context, wg *sync.WaitGroup) error {
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
