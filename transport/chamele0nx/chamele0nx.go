package chamele0nx

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meshoklv/chamele0nx/internal/chcrypto"
	"github.com/meshoklv/chamele0nx/transport"

	// v2.1: switched HTTP/2 client from golang.org/x/net/http2 to
	// github.com/bogdanfinn/fhttp/http2 to fix the H2 fingerprint
	// mismatch with Chrome (4 SETTINGS not 6, INITIAL_WINDOW_SIZE
	// 6291456, pseudo-header order m,a,s,p, ConnectionFlow 15663105).
	// Goes hand-in-hand with importing fhttp instead of net/http for
	// the Request type — fhttp/http2.Transport accepts *fhttp.Request,
	// not *net/http.Request. The two are field-compatible (fhttp is a
	// fork of net/http with extra HeaderOrderKey / PHeaderOrderKey).
	//
	// Note: fhttp/http2 internally aliases its TLS layer to
	// github.com/bogdanfinn/utls (NOT refraction-networking/utls). Our
	// dialChamele0nXUTLS still uses refraction-networking/utls for the
	// actual TLS handshake — that's intentional, the two utls forks
	// don't need to interop here because we hand fhttp/http2 a generic
	// net.Conn and let it run framing on top of our pre-handshaked TLS.
	// fhttp/http2's connectionStater type-assertion will fail (returns
	// our chamele0nxConnAdapter which has no ConnectionState method on
	// the bgnutls type), and that's fine — fhttp/http2 just leaves the
	// peer cert state nil, which the framer doesn't care about.
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	bgnutls "github.com/bogdanfinn/utls"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// Endpoint params for Chamele0nX transport:
//
//	"chameleon_addr"     -- server address, host:port (e.g., "app.example.com:443")
//	"chameleon_sni"      -- TLS SNI (defaults to host from chameleon_addr)
//	"chameleon_path"     -- API path for tunnel (e.g., "/api/v1/events")
//	"chameleon_cookie"   -- cookie format: "generic", "wordpress", "django"
//	"user_secret"        -- user's master secret for auth token generation,
//	                        hex-encoded (lowercase or uppercase). MUST decode
//	                        to at least 16 raw bytes. Hex is required because
//	                        endpoint params travel through JSON (gomobile,
//	                        invite blobs); raw bytes-as-string would not
//	                        survive UTF-8 round-trip.
//	"server_id"          -- server identifier for per-server token derivation
//	"chameleon_profile"  -- path to site profile JSON (optional, uses default if empty)

// minUserSecretBytes is the minimum length of the decoded user_secret.
// Matches the floor enforced by chamele0nx-server's secret loader.
const minUserSecretBytes = 16

// Transport implements transport.Transport for the Chamele0nX protocol.
type Transport struct {
	mu      sync.Mutex
	profile *SiteProfile

	// sessionCache is a TLS session ticket cache shared across every
	// reconnect this Transport makes. Chrome always presents a
	// pre-shared-key extension (TLS 1.3 session ticket) in ClientHello
	// when reconnecting to the same origin within ticket lifetime;
	// without this cache, every Chamele0nX reconnect would emit a full
	// "fresh" ClientHello with no session ticket, and that absent-ticket
	// state is visible to passive DPI as a fingerprint mismatch
	// against our Chrome 146 UA + Chrome 146 H2 SETTINGS. uTLS
	// auto-keys the cache on ServerName, so hitting multiple SNIs from
	// the same Transport stays correctly isolated.
	//
	// LRU of 32 is a safe default: one Transport persists for the whole
	// lifetime of a mobile client, and we rarely hit more than a handful
	// of distinct SNIs per installation. Bump it if SNI pool rotation
	// starts covering many more targets.
	sessionCache utls.ClientSessionCache

	// Handshake stats — observable metric so tests and ops can confirm
	// that session resumption is actually happening in the wild (and
	// not silently reverting to full handshakes because the cache got
	// invalidated or the remote doesn't issue tickets). Incremented
	// inside dialChamele0nXUTLS on every successful handshake.
	totalHandshakes   atomic.Uint64
	resumedHandshakes atomic.Uint64

	// tlsDialFn is an optional override for the underlying TLS dialer.
	// Production code uses dialChamele0nXUTLS (uTLS Chrome fingerprint).
	// Tests inject a stdlib tls.Dialer with InsecureSkipVerify and a
	// trusted self-signed cert so they don't need a real CA.
	tlsDialFn func(ctx context.Context, addr, sni string) (net.Conn, error)
}

// New creates a new Chamele0nX transport.
func New() *Transport {
	return &Transport{
		// 32 = plenty of slack for per-SNI isolation; see Transport.sessionCache doc.
		sessionCache: utls.NewLRUClientSessionCache(32),
	}
}

// HandshakeStats returns the total number of successful TLS handshakes
// this Transport has performed and how many of them were resumed via a
// cached session ticket (TLS 1.3 PSK). Exposed so tests and operators
// can verify the session cache is actually being hit.
func (t *Transport) HandshakeStats() (total, resumed uint64) {
	return t.totalHandshakes.Load(), t.resumedHandshakes.Load()
}

// Info returns static metadata describing the Chamele0nX transport.
func (t *Transport) Info() transport.Info {
	return transport.Info{
		Name:           "Chamele0nX",
		Type:           "chamele0nx",
		Priority:       1,               // primary transport
		MaxBandwidth:   5 * 1024 * 1024, // ~5 MB/s in stealth mode
		TypicalLatency: 200 * time.Millisecond,
		SupportsUDP:    false,
	}
}

// Probe reports whether the endpoint completes a Chamele0nX uTLS handshake,
// and how long that handshake took. It does not run the full Chamele0nX key
// exchange, so a successful probe means "reachable and speaking TLS", not
// "authenticated".
func (t *Transport) Probe(ctx context.Context, endpoint transport.Endpoint) (bool, time.Duration, error) {
	if err := validateChamele0nXParams(endpoint); err != nil {
		return false, 0, err
	}

	addr := endpoint.Params["chameleon_addr"]
	sni := resolveChamele0nXSNI(endpoint)

	start := time.Now()

	// TLS handshake via uTLS to verify server is reachable with valid TLS.
	conn, err := t.dialChamele0nXUTLS(ctx, addr, sni)
	if err != nil {
		return false, 0, fmt.Errorf("utls dial %s: %w", addr, err)
	}
	// The handshake already told us what the probe needed to know; failing
	// to close the throwaway connection cannot change that verdict.
	_ = conn.Close()

	return true, time.Since(start), nil
}

// Connect implements transport.Transport. Returns a tunnel with its own
// random-port SOCKS5 listener bound and ready. For long-running production
// use prefer PersistentClient — it manages a stable listener and handles
// reconnection automatically.
func (t *Transport) Connect(ctx context.Context, endpoint transport.Endpoint) (transport.Tunnel, error) {
	tun, err := t.connect(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	// Start local SOCKS5 proxy on a random free port.
	socksPort, err := findFreePort()
	if err != nil {
		// Tearing down a tunnel we are about to abandon; the caller gets
		// the reason Connect failed, which is strictly more useful.
		_ = tun.Close()
		return nil, fmt.Errorf("find free port: %w", err)
	}
	if err := tun.startSOCKS5(socksPort); err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("start socks5: %w", err)
	}

	return tun, nil
}

// connect performs the Chamele0nX handshake (TCP → uTLS → HTTP/2 POST →
// ECDH key exchange → AES-GCM session key → mux setup) and returns the
// resulting tunnel WITHOUT binding a SOCKS5 listener. Used by both:
//   - the public Connect (which then adds its own random-port SOCKS5)
//   - PersistentClient (which manages a stable listener separately)
//
// The returned tunnel's read loop is already running.
func (t *Transport) connect(ctx context.Context, endpoint transport.Endpoint) (*Tunnel, error) {
	if err := validateChamele0nXParams(endpoint); err != nil {
		return nil, fmt.Errorf("invalid chamele0nx endpoint: %w", err)
	}

	addr := endpoint.Params["chameleon_addr"]
	realSNI := resolveChamele0nXSNI(endpoint)
	apiPath := getParamOrDefault(endpoint.Params, "chameleon_path", "/api/v1/events")
	cookieFormat := getParamOrDefault(endpoint.Params, "chameleon_cookie", "generic")

	// ===== SNI substitution =====
	//
	// Some inspection deployments decide a flow's fate from the name in
	// the ClientHello and let it through when that name is one they
	// allow. Where that is so, advertising such a name is the only
	// lever that helps, because the decision is taken before any
	// application data exists to shape. See sni_pool.go for the pool and
	// docs/en/THREAT-MODEL.md for what this does and does not buy.
	//
	// Two activation paths, checked in order:
	//
	//   1. `chameleon_spoof` param == "off" → hard opt-out, standard
	//      cert validation, no SNI substitution. Escape hatch for debugging
	//      and for rolling back to plain-SNI behaviour.
	//
	//   2. `chameleon_pubkey_pin` in params → explicit hex-encoded
	//      32-byte pin, supplied by whoever provisions the server.
	//      Must be exactly 32 bytes (sha256 of the DER-encoded
	//      SubjectPublicKeyInfo) or validation fails.
	//
	// In pinned substitution mode (path 2):
	//   - ClientHello SNI = an allow-listed domain picked from
	//     substituteSNIPool (see sni_pool.go), which is what the DPI
	//     box sees when it decides to let the flow through.
	//   - HTTP/2 :authority / Host = the same whitelisted domain so
	//     inside-TLS layers stay consistent with what ClientHello
	//     advertised.
	//   - Standard cert name verification is bypassed; the peer cert's
	//     SubjectPublicKeyInfo sha256 is compared constant-time
	//     against the pinned value. MitM requires the server's
	//     private key.
	var pubkeyPin []byte
	substitutionOptOut := endpoint.Params["chameleon_spoof"] == "off"
	switch {
	case substitutionOptOut:
		// Explicit opt-out: leave pubkeyPin nil → plain-SNI behaviour.
	case endpoint.Params["chameleon_pubkey_pin"] != "":
		// Explicit pin — validate shape, use as-is.
		p, err := hex.DecodeString(endpoint.Params["chameleon_pubkey_pin"])
		if err != nil {
			return nil, fmt.Errorf("invalid chamele0nx endpoint: chameleon_pubkey_pin hex: %w", err)
		}
		if len(p) != 32 {
			return nil, fmt.Errorf("invalid chamele0nx endpoint: chameleon_pubkey_pin must be 32 bytes (sha256 of DER SubjectPublicKeyInfo), got %d", len(p))
		}
		pubkeyPin = p
	default:
		// No pin supplied → standard certificate validation and the
		// real SNI. SNI substitution requires an explicit pin, because
		// bypassing name verification without one would make the
		// client trivially MitM-able.
	}

	// Per-connection seed (used below for the profile personalization
	// and user-agent rotation) — hoisted up so we can reuse it for
	// the substituted-SNI selection, which must be stable for the whole
	// lifetime of this handshake.
	clientSeed := generateClientSeed()

	// SNI resolution: real SNI by default, pool pick when substitution.
	// authorityHost is what we put into the HTTP/2 :authority pseudo-
	// header and the net/http Request.Host field. In substitution mode both
	// the TLS SNI and :authority advertise the same whitelisted domain
	// so the layers are internally consistent (an active prober that
	// breaks into TLS would see "I came for apple.com and the server
	// answered as apple.com").
	sni := realSNI
	authorityHost := realSNI
	if len(pubkeyPin) > 0 {
		// An operator-supplied name always wins: one they actually control,
		// or one their own front terminates, is strictly better than
		// anything a generic pool can offer. Otherwise fall back to the
		// pool, keyed on this client's identity so the choice is the same
		// on every reconnect — see pickSubstituteSNI for why rotating it
		// was worse than useless.
		substituteSNI := endpoint.Params["chameleon_spoof_sni"]
		if substituteSNI == "" {
			substituteSNI = pickSubstituteSNI(substitutionIdentity(endpoint))
		}
		sni = substituteSNI
		authorityHost = substituteSNI
		// Deliberately without values. The real name is the operator's
		// domain and the substituted one is the choice an observer would
		// most like to learn; neither belongs in a log file. See the
		// logging rules in docs/en/OPERATIONS.md.
		slog.Debug("chamele0nx: SNI substitution active")
	}
	// user_secret is hex-encoded so it can survive JSON round-trip from
	// gomobile/invite paths. validateChamele0nXParams already verified the
	// hex shape and minimum length, so DecodeString here can only fail on
	// a logic bug.
	userSecret, err := hex.DecodeString(endpoint.Params["user_secret"])
	if err != nil {
		return nil, fmt.Errorf("invalid chamele0nx endpoint: user_secret hex: %w", err)
	}
	serverID := endpoint.Params["server_id"]
	if serverID == "" {
		serverID = endpoint.ID
	}
	defer chcrypto.Zeroize(userSecret)

	// Generate auth token.
	token := GenerateAuthToken(userSecret, serverID)
	cookie := FormatCookie(token, cookieFormat)

	// Load or use default profile. Resolution order:
	//   1. params["chameleon_profile"] is empty            → DefaultClientUpstreamProfile
	//   2. matches a built-in name (stealth/balanced/...)  → built-in struct
	//   3. otherwise treated as a filesystem path           → LoadProfile(path)
	//
	// The built-in branch exists so mobile clients can ship 5+ distinct
	// preset configs (Stealth/Balanced/Aggressive/WordPress/LowPower)
	// without bundling JSON profile files into the app package and
	// staging them onto the device filesystem at runtime.
	t.mu.Lock()
	if t.profile == nil {
		p, err := resolveProfile(endpoint.Params["chameleon_profile"])
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		t.profile = p
	}
	profile := t.profile
	t.mu.Unlock()

	// clientSeed was hoisted to the top of connect() so the SNI
	// path could reuse it for pickSubstituteSNI. It's still the same
	// per-connection seed used for TLS record size jitter (FOCI 2024)
	// and downstream for PersonalizeFor below.

	// Personalize the profile for this client. Without this
	// every Chamele0nX user shares identical bucket envelopes and burst
	// patterns and is mutually correlatable on the wire. PersonalizeFor
	// jitters the envelope itself (weights ±20%, RecordsPerBurst ±30%,
	// InterBurstPause ±50%) deterministically from clientSeed, so two
	// users on the same nominal preset look like two users on slightly
	// different real sites. Stable within this connection, divergent
	// between connections.
	profile = profile.PersonalizeFor(clientSeed)

	// Generate ECDH X25519 keypair for forward secrecy.
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh keygen: %w", err)
	}

	// HTTP/2 transport with uTLS (Chrome fingerprint).
	// Tests can override the dialer via t.tlsDialFn (see newTestTransport).
	//
	// In substitution mode we wrap dialUTLSWith with the pinned public key so
	// the standard cert validation is replaced with SPKI-hash
	// comparison. Without a pin this reduces to the normal dial path.
	// Tests that override tlsDialFn win over both (standard and
	// substituted) so unit tests can keep using stdlib TLS dialers.
	var dialFn func(ctx context.Context, addr, sni string) (net.Conn, error)
	switch {
	case t.tlsDialFn != nil:
		dialFn = t.tlsDialFn
	case len(pubkeyPin) > 0:
		dialFn = func(ctx context.Context, addr, sni string) (net.Conn, error) {
			return t.dialUTLSWith(ctx, addr, sni, pubkeyPin)
		}
	default:
		dialFn = t.dialChamele0nXUTLS
	}

	// fhttp/http2.Transport with an explicit Chrome 146 H2
	// fingerprint. Settings are 4-entry exactly matching what real
	// Chrome 120-146 sends (per scrapfly.io HTTP/2 fingerprint guide
	// + Akamai whitepaper). MaxConcurrentStreams and MaxFrameSize are
	// NOT in the set — Chrome doesn't advertise them.
	//
	// ConnectionFlow=15663105 is the magic initial WINDOW_UPDATE Chrome
	// emits right after SETTINGS, observed in every modern Chrome capture.
	//
	// PseudoHeaderOrder is the load-bearing one: stdlib http2 sends
	// :method :scheme :authority :path; Chrome sends m,a,s,p. Akamai-class
	// detectors fingerprint on this single difference.
	//
	// DialTLS in fhttp/http2 has a different signature than stdlib's
	// DialTLSContext — no context, and the cfg is *bgnutls.Config not
	// *stdtls.Config. We ignore the cfg (dialChamele0nXUTLS runs its own
	// handshake with refraction-networking/utls) but we do close over the
	// ctx handed to connect, so cancelling that context aborts the TLS
	// handshake instead of waiting out the 15s net.Dialer timeout. The
	// dial happens once, inside this call to connect, so a ctx cancelled
	// after the tunnel is up cannot disturb the established tunnel.
	h2t := &http2.Transport{
		DialTLS: func(network, _ string, _ *bgnutls.Config) (net.Conn, error) {
			conn, err := dialFn(ctx, addr, sni)
			if err != nil {
				return nil, err
			}
			// Shape TLS records to match the cover site profile.
			// MUST sit between TLS and the H2 framer — that's why we
			// can't use bogdanfinn/tls-client (it owns the TLS layer
			// internally and doesn't expose this seam).
			return NewShapedConn(conn, profile, clientSeed), nil
		},
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		ConnectionFlow:    15663105, // Chrome's initial WINDOW_UPDATE delta
		InitialWindowSize: 6291456,  // mirror SettingInitialWindowSize, fhttp uses both fields
		HeaderTableSize:   65536,    // mirror SettingHeaderTableSize
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},

		AllowHTTP:          false,
		DisableCompression: true,
		// ReadIdleTimeout is deliberately left zero. A non-zero value
		// makes the HTTP/2 transport emit an automatic PING on every
		// idle interval, which puts a fixed-size record on the wire at a
		// fixed period in both directions — a clean periodic signal no
		// ordinary browser produces on an idle connection. Dead-tunnel
		// detection instead falls back to the per-stream idle deadlines
		// on the relay, which is slower but carries no timing signature.
	}

	// Create bidirectional tunnel via HTTP/2 POST.
	// Request body = client → server (encrypted VPN data).
	// Response body = server → client (encrypted VPN data).
	pr, pw := io.Pipe()

	// authorityHost controls the HTTP/2 :authority pseudo-header and
	// Request.Host. In substitution mode it equals the whitelisted SNI so
	// the inside-TLS layers look self-consistent to anything that
	// decrypts the stream. In normal mode it equals the real SNI.
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   authorityHost,
			Path:   apiPath,
		},
		Host:   authorityHost,
		Header: make(http.Header),
		Body:   pr,
	}

	// Set auth cookie (format matches cover site).
	req.Header.Set("Cookie", cookie)
	// Content-Type matching a real API.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// User-Agent picked from a pool of 10 currently-realistic browser
	// strings, derived deterministically from clientSeed so it stays
	// stable for the lifetime of this connection. A single hardcoded
	// User-Agent would let an active prober group every Chamele0nX user
	// behind one fingerprint. The pool lives in useragent.go and must
	// be refreshed when browser major versions roll.
	req.Header.Set("User-Agent", pickUserAgent(clientSeed))

	// Explicit HEADERS frame field order matching real Chrome
	// requests. PHeaderOrderKey controls pseudo-headers (also set on
	// Transport.PseudoHeaderOrder above as a fallback). HeaderOrderKey
	// controls regular headers — Chrome typically sends Cookie first,
	// then Content-Type, then Accept, then User-Agent on POST requests
	// to JSON APIs (observed in Chrome devtools network tab).
	req.Header[http.HeaderOrderKey] = []string{"cookie", "content-type", "accept", "user-agent"}
	req.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}

	resp, err := h2t.RoundTrip(req)
	if err != nil {
		// From here on every failure path tears down the half-built
		// tunnel. Close errors on the pipe and on the response body add
		// nothing to the handshake error we are already returning.
		_ = pw.Close()
		return nil, fmt.Errorf("h2 post: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// Key exchange: send our ECDH public key, receive server's. The write
	// is padded to a random size so the key-exchange record is not a
	// fixed constant at the start of every session — see
	// writeKeyExchangeFrame.
	pubKeyBytes := privKey.PublicKey().Bytes()
	if err := writeKeyExchangeFrame(pw, pubKeyBytes); err != nil {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("send pubkey: %w", err)
	}

	// Read server's public key.
	serverFrame, err := ReadFrame(resp.Body)
	if err != nil {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("read server pubkey: %w", err)
	}
	if serverFrame.Type != frameKeyExchange || len(serverFrame.Payload) != 32 {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("invalid server key exchange frame")
	}

	serverPubKey, err := ecdh.X25519().NewPublicKey(serverFrame.Payload)
	if err != nil {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("parse server pubkey: %w", err)
	}

	// Derive shared secret via X25519 ECDH.
	sharedSecret, err := privKey.ECDH(serverPubKey)
	if err != nil {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// Derive AES-256-GCM key via HKDF.
	sessionKey, err := deriveSessionKey(sharedSecret)
	chcrypto.Zeroize(sharedSecret)
	if err != nil {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, err
	}

	keyGuard := newSessionKeyGuard(sessionKey)

	var writeMu sync.Mutex
	writeFn := func(payload []byte) error {
		ct, err := keyGuard.encrypt(payload)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return WriteFrame(pw, Frame{Type: frameData, Payload: ct})
	}

	mux := NewMux(writeFn)

	tun := &Tunnel{
		writer:     pw,
		reader:     resp.Body,
		h2t:        h2t,
		sessionKey: keyGuard,
		mux:        mux,
		endpoint:   endpoint,
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		remoteAddr: parseAddr(addr),
		done:       make(chan struct{}),
	}

	// Start reader goroutine: decrypts incoming frames and dispatches to mux.
	go tun.readLoop()

	return tun, nil
}

// resolveProfile turns a `chameleon_profile` param into a concrete
// profile, following the order documented at its only call site: empty →
// the client-upstream default, a known preset name → that preset,
// anything else → a JSON file on disk.
func resolveProfile(profileVal string) (*SiteProfile, error) {
	if profileVal == "" {
		// Not DefaultSaaSProfile: its 5–15 record bursts and 50–250ms
		// inter-burst pauses cap this half of the tunnel near 0.2 MB/s,
		// measured at 0.12 MB/s against production on 2026-09-09. See
		// DefaultClientUpstreamProfile for the full rationale.
		return DefaultClientUpstreamProfile(), nil
	}
	if p := BuiltInProfileByName(profileVal); p != nil {
		return p, nil
	}
	p, err := LoadProfile(profileVal)
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}
	return p, nil
}

// Close releases transport-level resources. Tunnels own their own
// connections and must be closed separately, so there is nothing to tear
// down here and Close never fails.
func (t *Transport) Close() error {
	return nil
}

// Tunnel is an established Chamele0nX connection with a local SOCKS5 proxy.
// Implements transport.Tunnel. Use SocksAddr() to get the local SOCKS5 address.
type Tunnel struct {
	writer     *io.PipeWriter // client → server (request body)
	reader     io.ReadCloser  // server → client (response body)
	h2t        *http2.Transport
	sessionKey *sessionKeyGuard
	mux        *Mux
	endpoint   transport.Endpoint
	localAddr  net.Addr
	remoteAddr net.Addr
	socksAddr  string

	listener net.Listener
	closed   bool
	closeMu  sync.Mutex

	// done is closed exactly once when the tunnel becomes unusable
	// (read loop exited, Close called, or fatal write error). Used by
	// PersistentClient to detect tunnel death and trigger reconnect.
	done     chan struct{}
	doneOnce sync.Once
}

// signalDone closes the done channel exactly once. Safe to call from any
// goroutine; subsequent calls are no-ops.
func (tun *Tunnel) signalDone() {
	tun.doneOnce.Do(func() {
		if tun.done != nil {
			close(tun.done)
		}
	})
}

// Done returns a channel that is closed when the tunnel becomes unusable
// (read loop exited, write error, or Close called). Used by reconnect logic
// to detect tunnel death without polling.
func (tun *Tunnel) Done() <-chan struct{} {
	return tun.done
}

// IsClosed reports whether Close has been called on this tunnel.
func (tun *Tunnel) IsClosed() bool {
	tun.closeMu.Lock()
	defer tun.closeMu.Unlock()
	return tun.closed
}

// Mux returns the underlying stream multiplexer. Used by PersistentClient
// to open streams on the current active tunnel. Do not close the mux directly —
// call Close on the tunnel instead.
func (tun *Tunnel) Mux() *Mux { return tun.mux }

// Read is not used directly — use the SOCKS5 proxy at SocksAddr().
func (tun *Tunnel) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("chamele0nx tunnel uses SOCKS5 proxy at %s; use SocksAddr()", tun.socksAddr)
}

// Write is not used directly — use the SOCKS5 proxy at SocksAddr().
func (tun *Tunnel) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("chamele0nx tunnel uses SOCKS5 proxy at %s; use SocksAddr()", tun.socksAddr)
}

// Close tears the tunnel down: it closes the mux, sends a best-effort close
// frame to the server, closes both halves of the HTTP/2 body pipe and the
// SOCKS5 listener, wipes the session key and signals Done. Close is
// idempotent and never reports a failure — once teardown has begun there is
// nothing a caller could usefully do about a failing sub-close, and the
// tunnel is unusable either way.
func (tun *Tunnel) Close() error {
	tun.closeMu.Lock()
	defer tun.closeMu.Unlock()
	if tun.closed {
		return nil
	}
	tun.closed = true

	if tun.mux != nil {
		tun.mux.Close()
	}
	// Send close frame. Best effort: the peer treats a dropped connection
	// the same as an explicit close frame, so a failure here is harmless.
	_ = WriteFrame(tun.writer, Frame{Type: frameClose})
	_ = tun.writer.Close()
	_ = tun.reader.Close()
	if tun.listener != nil {
		_ = tun.listener.Close()
	}
	if tun.h2t != nil {
		tun.h2t.CloseIdleConnections()
	}
	tun.sessionKey.destroy()
	tun.signalDone()
	return nil
}

// LocalAddr returns the address of the tunnel's local SOCKS5 listener.
// Before startSOCKS5 has run there is no listener and the port is reported
// as 0.
func (tun *Tunnel) LocalAddr() net.Addr {
	host, portStr, _ := net.SplitHostPort(tun.socksAddr)
	// An unparseable port means the listener is not up yet; 0 is the right
	// answer in that case, so a conversion failure needs no handling.
	port, _ := strconv.Atoi(portStr)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

// RemoteAddr returns the address of the Chamele0nX server this tunnel is
// connected to.
func (tun *Tunnel) RemoteAddr() net.Addr { return tun.remoteAddr }

// SocksAddr returns the local SOCKS5 proxy address (127.0.0.1:port).
func (tun *Tunnel) SocksAddr() string { return tun.socksAddr }

// readLoop decrypts incoming tunnel frames and dispatches to the mux.
// On any exit (read error, decrypt failure, or close frame) the tunnel's
// done channel is closed so reconnect logic can detect death.
func (tun *Tunnel) readLoop() {
	defer tun.signalDone()
	for {
		frame, err := ReadFrame(tun.reader)
		if err != nil {
			return
		}

		switch frame.Type {
		case frameData:
			plaintext, err := tun.sessionKey.decrypt(frame.Payload)
			if err != nil {
				return
			}
			sf, err := DecodeStreamFrame(plaintext)
			if err != nil {
				continue
			}
			tun.mux.Deliver(sf)

		case framePing:
			// Ignore pings from server.
		case frameClose:
			return
		}
	}
}

// startSOCKS5 starts a minimal SOCKS5 proxy that tunnels each TCP connection
// through a mux stream to the Chamele0nX server.
func (tun *Tunnel) startSOCKS5(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	tun.listener = ln
	tun.socksAddr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go tun.handleSOCKS5(conn)
		}
	}()
	return nil
}

// handleSOCKS5 implements SOCKS5 (RFC 1928) for one client connection.
func (tun *Tunnel) handleSOCKS5(clientConn net.Conn) {
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
		// UDP ASSOCIATE — relay datagrams through the mux (udp_client.go).
		// The control conn stays open as the association lifetime.
		handleUDPAssociate(clientConn, tun.mux)
		return
	default:
		// BIND / unknown. Reply success + bind 0.0.0.0:0 and close so apps
		// fall back cleanly (see persistent.go for the historical rationale).
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

	// 5. Open mux stream to server.
	stream, err := tun.mux.OpenStream(host, port)
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

	// 7. Relay bidirectionally.
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

	// One direction finished; close both ends so the other relay goroutine
	// unblocks, then wait for it. Close errors here only mean the peer has
	// already hung up, which is the expected way for a relay to end.
	<-done
	_ = clientConn.Close()
	_ = stream.Close()
	<-done
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	// Release the port before handing it to the caller: if the close fails
	// the port is still held and binding to it would fail confusingly.
	if err := l.Close(); err != nil {
		return 0, fmt.Errorf("release probe listener: %w", err)
	}
	return port, nil
}

// deriveSessionKey derives an AES-256-GCM key from the ECDH shared secret.
func deriveSessionKey(sharedSecret []byte) ([]byte, error) {
	// Use HKDF-SHA256 with the Chamele0nX context string.
	key := make([]byte, 32)
	hkdfReader := hmacHKDF(sharedSecret, nil, []byte("chameleon-session-v1"))
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("hkdf derive session key: %w", err)
	}
	return key, nil
}

// hmacHKDF is a thin wrapper around HKDF-SHA256.
func hmacHKDF(secret, salt, info []byte) io.Reader {
	return hkdf.New(sha256.New, secret, salt, info)
}

// --- uTLS dialing ---

// newUTLSConfig builds a baseline *utls.Config for every client dial on the
// Chamele0nX transport. It lives in its own function so the invariants below
// have a direct unit test anchor — see TestNewUTLSConfigEnforcesCriticalRules
// in chamele0nx_test.go.
//
// Every field here is load-bearing:
//
//   - ServerName: SNI the caller wants advertised in ClientHello. In
//     mode this is an allow-listed name (apple.com etc.); in normal mode
//     it's the real Chamele0nX server hostname.
//   - ClientSessionCache: matches Chrome behaviour on reconnect — Chrome
//     presents a cached session ticket, so must we.
//   - DynamicRecordSizingDisabled: if this is false, uTLS falls back to
//     stdlib TLS behaviour and ramps record size 512B → 1KB → ... → 16KB
//     over the first ~128KB of data. ShapedConn cannot compensate — it
//     lives on top of the TLS layer, and the fragmentation happens
//     underneath it. On mobile those first 2–5 seconds are exactly the
//     window a DPI box uses to classify VPN traffic versus a real site.
//     An earlier revision omitted this flag on the client while the
//     server set it, which produced a clean client/server asymmetry
//     visible in every session.
//
// Do not add fields here without documenting the rule they serve, and do
// not remove DynamicRecordSizingDisabled.
func (t *Transport) newUTLSConfig(sni string) *utls.Config {
	return &utls.Config{
		ServerName:                  sni,
		ClientSessionCache:          t.sessionCache,
		DynamicRecordSizingDisabled: true, // never let TLS ramp record sizes
	}
}

// dialChamele0nXUTLS establishes a TLS connection with Chrome fingerprint.
// Uses DynamicRecordSizingDisabled on the underlying connection for TLS record control.
//
// This is a method rather than a package-level function so it can read
// t.sessionCache and t.total/resumedHandshakes without global state or
// closures.
//
// The utls.Config carries a ClientSessionCache pointer so
// that every subsequent reconnect to the same ServerName can present
// a cached session ticket in ClientHello — matching what a real Chrome
// does on reconnect, and closing the "absent session ticket extension"
// mismatch surfaced by the external security review.
func (t *Transport) dialChamele0nXUTLS(ctx context.Context, addr, sni string) (net.Conn, error) {
	// Normal (non-substitution) path: no pubkey pin, standard cert verification.
	return t.dialUTLSWith(ctx, addr, sni, nil)
}

// dialUTLSWith is the shared implementation behind dialChamele0nXUTLS and
// the SNI-substitution path. When pubkeyPin is nil it behaves like a plain
// dialer — standard cert verification, ServerName == real SNI. When
// pubkeyPin is non-nil:
//
//  1. The SNI in ClientHello becomes whatever the caller passes as `sni`
//     (typically a value picked from substituteSNIPool) so the DPI box
//     sees an allow-listed name and lets the flow through its 16KB
//     inspection window.
//  2. Normal cert name verification is disabled (InsecureSkipVerify=true);
//     if we left it on, TLS would reject the cert because its SAN list
//     contains vpn.example.com, not apple.com.
//  3. Instead, we install a VerifyPeerCertificate callback that hashes
//     the first peer cert's SubjectPublicKeyInfo and compares it
//     constant-time against the pinned sha256. An attacker cannot
//     forge this without the server's private key, so MitM resistance
//     is equivalent to (or stronger than) a CA-based trust path.
//
// The ClientSessionCache pointer is threaded through either way so
// TLS 1.3 session tickets work in both modes.
func (t *Transport) dialUTLSWith(ctx context.Context, addr, sni string, pubkeyPin []byte) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 15 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	cfg := t.newUTLSConfig(sni)

	substitution := len(pubkeyPin) > 0
	if substitution {
		// Disable standard cert validation — we'd fail on SAN mismatch
		// because the server presents a cert for vpn.example.com while
		// ClientHello advertises apple.com (or whatever we picked).
		cfg.InsecureSkipVerify = true
		// Copy the pin so the callback closure isn't racing with a
		// future caller mutating the input slice.
		pin := make([]byte, len(pubkeyPin))
		copy(pin, pubkeyPin)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("chamele0nx tls: no peer certs presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("chamele0nx tls: parse peer cert: %w", err)
			}
			spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("chamele0nx tls: marshal peer pubkey: %w", err)
			}
			got := sha256.Sum256(spkiDER)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return fmt.Errorf("chamele0nx tls: pubkey pin mismatch (peer sha256 prefix %x, expected %x)",
					got[:4], pin[:4])
			}
			return nil
		}
	}

	uconn := utls.UClient(tcpConn, cfg, utls.HelloChrome_Auto)

	if err := uconn.HandshakeContext(ctx); err != nil {
		// Handshake failed; the TCP connection is unusable and the caller
		// only cares about why the handshake failed.
		_ = tcpConn.Close()
		if substitution {
			return nil, fmt.Errorf("utls substituted handshake: %w", err)
		}
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	state := uconn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		// Wrong ALPN — discard the connection; the returned error is what
		// the caller acts on.
		_ = uconn.Close()
		return nil, fmt.Errorf("ALPN: expected h2, got %q", state.NegotiatedProtocol)
	}

	t.totalHandshakes.Add(1)
	if state.DidResume {
		t.resumedHandshakes.Add(1)
		slog.Debug("chamele0nx tls: session resumed (PSK)", "sni_substituted", substitution)
	} else {
		slog.Debug("chamele0nx tls: full handshake", "sni_substituted", substitution)
	}

	return &chamele0nxConnAdapter{uconn: uconn, tcp: tcpConn}, nil
}

// chamele0nxConnAdapter wraps utls.UConn for http2.Transport compatibility.
type chamele0nxConnAdapter struct {
	uconn *utls.UConn
	tcp   net.Conn
}

func (a *chamele0nxConnAdapter) Read(p []byte) (int, error)        { return a.uconn.Read(p) }
func (a *chamele0nxConnAdapter) Write(p []byte) (int, error)       { return a.uconn.Write(p) }
func (a *chamele0nxConnAdapter) Close() error                      { return a.uconn.Close() }
func (a *chamele0nxConnAdapter) LocalAddr() net.Addr               { return a.tcp.LocalAddr() }
func (a *chamele0nxConnAdapter) RemoteAddr() net.Addr              { return a.tcp.RemoteAddr() }
func (a *chamele0nxConnAdapter) SetDeadline(t time.Time) error     { return a.uconn.SetDeadline(t) }
func (a *chamele0nxConnAdapter) SetReadDeadline(t time.Time) error { return a.uconn.SetReadDeadline(t) }
func (a *chamele0nxConnAdapter) SetWriteDeadline(t time.Time) error {
	return a.uconn.SetWriteDeadline(t)
}

// v2.1: ConnectionState() removed. It was only needed by stdlib's
// x/net/http2 connectionStater interface, which returned crypto/tls.
// ConnectionState. fhttp/http2 expects bgnutls.ConnectionState (a
// different fork), so even if we kept the method it wouldn't match
// fhttp's interface. fhttp/http2 just leaves cc.tlsState nil when
// the conn doesn't implement its connectionStater — that's fine for
// our use case (we don't read peer cert info from the H2 framer).

// --- helpers ---

// substitutionIdentity returns the material the substitute-name choice is
// derived from: this user's secret and this server's address. It is stable
// across reconnects, so a client keeps one name for as long as it keeps its
// credentials, and two users of the same server get different names.
//
// The secret is hashed inside pickSubstituteSNI and never leaves this
// process; only the resulting pool index has any outward effect.
func substitutionIdentity(ep transport.Endpoint) []byte {
	return []byte(ep.Params["user_secret"] + "@" + ep.Params["chameleon_addr"])
}

// validateHostname accepts the shape of a DNS name that may appear in a
// ClientHello: labels of letters, digits and hyphens, separated by dots, no
// scheme, no port, no trailing dot.
func validateHostname(h string) error {
	if len(h) == 0 || len(h) > 253 {
		return fmt.Errorf("must be 1-253 characters, got %d", len(h))
	}
	if strings.ContainsAny(h, ":/ ") {
		return fmt.Errorf("must be a bare hostname, without scheme, port or spaces")
	}
	// RFC 6066 5.1: the SNI host_name is a DNS name. A literal address is
	// not one, and neither is a single label with no dot — both would be
	// conspicuous in a ClientHello.
	if net.ParseIP(h) != nil {
		return fmt.Errorf("must be a DNS name, not an IP address")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must have at least two labels, got %q", h)
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("each label must be 1-63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("labels must not start or end with a hyphen")
		}
		for _, r := range label {
			isDigit := r >= '0' && r <= '9'
			isLower := r >= 'a' && r <= 'z'
			isUpper := r >= 'A' && r <= 'Z'
			if !isDigit && !isLower && !isUpper && r != '-' {
				return fmt.Errorf("invalid character %q", r)
			}
		}
	}
	return nil
}

func validateChamele0nXParams(ep transport.Endpoint) error {
	if ep.Params["chameleon_addr"] == "" {
		return fmt.Errorf("missing required param: chameleon_addr")
	}
	secretHex := ep.Params["user_secret"]
	if secretHex == "" {
		return fmt.Errorf("missing required param: user_secret")
	}
	// Validate the hex shape early so the reconnect-loop classifier sees
	// "invalid chamele0nx endpoint" → fatal class instead of looping forever
	// on a malformed secret.
	decoded, err := hex.DecodeString(secretHex)
	if err != nil {
		return fmt.Errorf("user_secret must be hex-encoded: %w", err)
	}
	if len(decoded) < minUserSecretBytes {
		return fmt.Errorf("user_secret too short: %d bytes (need ≥%d)", len(decoded), minUserSecretBytes)
	}
	// If the endpoint specifies a cover profile, validate that it is
	// registered in THIS build. An empty string is allowed and resolves
	// to DefaultCoverID at connect time, so invite blobs written before
	// cover profiles existed keep working unchanged. Unknown cover names
	// are rejected up front with a descriptive error listing what IS
	// available, so a client running an old build does not silently fall
	// back to the default cover when a different one was requested.
	if coverID := ep.Params["cover"]; coverID != "" {
		if _, err := ResolveCover(coverID); err != nil {
			return fmt.Errorf("invalid chamele0nx endpoint: %w", err)
		}
	}
	// A substitute name is only meaningful in substitution mode, and it goes
	// straight into a ClientHello, so reject anything that is not a hostname
	// rather than putting a malformed value on the wire.
	if spoof := ep.Params["chameleon_spoof_sni"]; spoof != "" {
		if err := validateHostname(spoof); err != nil {
			return fmt.Errorf("invalid chamele0nx endpoint: chameleon_spoof_sni: %w", err)
		}
		switch {
		case ep.Params["chameleon_spoof"] == "off":
			return fmt.Errorf("invalid chamele0nx endpoint: chameleon_spoof_sni is set " +
				"while chameleon_spoof=off, so the name would never be used")
		case ep.Params["chameleon_pubkey_pin"] == "":
			return fmt.Errorf("invalid chamele0nx endpoint: chameleon_spoof_sni needs chameleon_pubkey_pin, " +
				"because substituting a name without pinning the key removes certificate verification")
		}
	}
	return nil
}

func resolveChamele0nXSNI(ep transport.Endpoint) string {
	if sni := ep.Params["chameleon_sni"]; sni != "" {
		return sni
	}
	host, _, err := net.SplitHostPort(ep.Params["chameleon_addr"])
	if err != nil {
		return ep.Params["chameleon_addr"]
	}
	return host
}

func getParamOrDefault(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

func parseAddr(addr string) net.Addr {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 443}
	}
	port := 443
	// A malformed port keeps the 443 default — this helper only builds a
	// net.Addr for display and bookkeeping, never for dialling.
	if p, convErr := strconv.Atoi(portStr); convErr == nil {
		port = p
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	return &net.TCPAddr{IP: ip, Port: port}
}
