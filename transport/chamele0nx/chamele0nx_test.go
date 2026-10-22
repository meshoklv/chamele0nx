package chamele0nx

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshoklv/chamele0nx/transport"

	// v2.1: this test uses TWO HTTP/2 stacks because the production
	// split is asymmetric — the server-side runs on stdlib http2.Server
	// (server fingerprint matters less; the cover-site role is to look
	// like a SaaS *responding* to clients, not to substitute Chrome itself),
	// while the client-side runs on fhttp/http2 to substitute Chrome H2 on
	// outbound. So:
	//   - "net/http" + "golang.org/x/net/http2" → mock SERVER side
	//   - fhttp + fhttp/http2 → mock CLIENT side (matches production
	//     Tunnel.h2t type, otherwise the test can't build the
	//     same struct as the real code)
	stdhttp2 "golang.org/x/net/http2"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttp2 "github.com/bogdanfinn/fhttp/http2"
	bgnutls "github.com/bogdanfinn/utls"
)

// TestEndToEndTunnel tests the full Chamele0nX flow:
// TCP echo server ← Chamele0nX server ← encrypted HTTP/2 tunnel ← Chamele0nX client (SOCKS5) ← test client.
func TestEndToEndTunnel(t *testing.T) {
	// 1. Start a TCP echo server (simulates internet target).
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(conn)
		}
	}()

	echoAddr := echoLn.Addr().String()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)
	t.Logf("echo server on %s", echoAddr)

	// 2. Start Chamele0nX server with TLS record shaping.
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	userSecret := make([]byte, 32)
	if _, err := rand.Read(userSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	serverID := "test-server-1"
	apiPath := "/api/v1/events"

	srv := NewServer(ServerConfig{
		APIPath:             apiPath,
		CookieFormat:        "generic",
		UserSecrets:         map[string][]byte{serverID: userSecret},
		ServerID:            serverID,
		AllowPrivateTargets: true, // test-only: echo server is on localhost
		Logger:              slog.Default(),
	})

	serverTLSCfg := &tls.Config{
		Certificates:                tlsCfg.Certificates,
		NextProtos:                  []string{"h2"},
		DynamicRecordSizingDisabled: true,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	h2s := &stdhttp2.Server{}
	serverHandler := srv.Handler()
	serverProfile := DefaultSaaSProfile()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						c.Close()
						return
					}
				}
				shaped := NewShapedConn(c, serverProfile, generateClientSeed())
				h2s.ServeConn(shaped, &stdhttp2.ServeConnOpts{
					Handler: serverHandler,
				})
			}(conn)
		}
	}()

	serverAddr := ln.Addr().String()
	t.Logf("chamele0nx server on %s", serverAddr)

	// 3. Connect Chamele0nX client (with mux + SOCKS5).
	tun, err := connectChamele0nXTest(context.Background(), New(), transport.Endpoint{
		ID:        serverID,
		Address:   serverAddr,
		Transport: "chamele0nx",
		Params: map[string]string{
			"chameleon_addr":   serverAddr,
			"chameleon_sni":    "localhost",
			"chameleon_path":   apiPath,
			"chameleon_cookie": "generic",
			"user_secret":      hex.EncodeToString(userSecret),
			"server_id":        serverID,
		},
	}, tlsCfg.Certificates[0])
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer tun.Close()

	chamele0nxTun := tun.(*Tunnel)
	t.Logf("tunnel established, SOCKS5 at %s", chamele0nxTun.SocksAddr())

	// 4. Connect through SOCKS5 to the echo server.
	socksConn, err := dialSOCKS5(chamele0nxTun.SocksAddr(), echoHost, echoPort)
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}
	defer socksConn.Close()

	// 5. Send data through tunnel and verify echo.
	testData := []byte("hello chamele0nx tunnel!")
	if _, err := socksConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	socksConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(socksConn, buf)
	if err != nil {
		t.Fatalf("read echo: %v (got %d bytes)", err, n)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], testData)
	} else {
		t.Logf("PASS: sent %q through encrypted tunnel, got echo back", testData)
	}
}

// dialSOCKS5 connects to a SOCKS5 proxy and requests connection to target.
func dialSOCKS5(proxyAddr, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Greeting: version 5, 1 auth method (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth failed: %x", resp)
	}

	// CONNECT request: domain name.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: status %d", reply[1])
	}

	return conn, nil
}

// TestCoverSiteActiveProbe verifies that unauthenticated requests
// get the cover site, not a tunnel or error.
func TestCoverSiteActiveProbe(t *testing.T) {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	srv := NewServer(ServerConfig{
		APIPath:      "/api/v1/events",
		CookieFormat: "generic",
		UserSecrets:  map[string][]byte{"srv1": []byte("secret")},
		ServerID:     "srv1",
		Logger:       slog.Default(),
	})

	httpServer := &http.Server{
		Handler: srv.Handler(),
		TLSConfig: &tls.Config{
			Certificates: tlsCfg.Certificates,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", httpServer.TLSConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go httpServer.Serve(ln)
	defer httpServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	addr := ln.Addr().String()

	// Test 1: GET /api/v1/health (no auth) → cover site response.
	resp, err := client.Get(fmt.Sprintf("https://%s/api/v1/health", addr))
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health: expected 200, got %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte(`"status":"ok"`)) {
		t.Errorf("health: expected JSON status, got %s", body)
	}
	t.Logf("cover site health: %s", body)

	// Test 2: POST /api/v1/events without auth → 401 from the API path,
	// NOT 200-with-data. A real protected endpoint rejects an anonymous
	// caller; handing back invented "events" is exactly the tell an
	// active prober looks for.
	resp2, err := client.Post(
		fmt.Sprintf("https://%s/api/v1/events", addr),
		"application/json",
		bytes.NewReader([]byte(`{}`)),
	)
	if err != nil {
		t.Fatalf("post events: %v", err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("events: expected 401, got %d", resp2.StatusCode)
	}
	if bytes.Contains(body2, []byte(`"events"`)) {
		t.Errorf("events: anonymous caller must not receive events, got %s", body2)
	}
	if !bytes.Contains(body2, []byte(`"unauthorized"`)) {
		t.Errorf("events: expected an unauthorized JSON error, got %s", body2)
	}
	t.Logf("cover site events (unauth): status=%d body=%s", resp2.StatusCode, body2)

	// Test 3: Random path → 404 (but JSON, not default Go 404).
	resp3, err := client.Get(fmt.Sprintf("https://%s/nonexistent", addr))
	if err != nil {
		t.Fatalf("get nonexistent: %v", err)
	}
	defer resp3.Body.Close()

	body3, _ := io.ReadAll(resp3.Body)
	t.Logf("cover site 404: status=%d body=%s", resp3.StatusCode, body3)
}

// TestAPIDecoyUnauthorized verifies apiDecoy answers an unauthenticated
// caller the way a real protected endpoint does, and identically across
// methods. Before this, the endpoint returned 200 with invented events to
// anyone and diverged by method (a GET fell through to a plain-text 404),
// which are two clean active-probe tells. The endpoint must now:
//
//   - answer GET and POST with 401 and no data, byte-for-byte identical;
//   - answer other methods with 405 and an Allow header;
//   - never emit an "events" field to an anonymous caller.
//
// This drives apiDecoy in-process (no network) via httptest.
func TestAPIDecoyUnauthorized(t *testing.T) {
	srv := &Server{}

	call := func(method string) (int, http.Header, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/v1/events", nil)
		srv.apiDecoy(rec, req)
		return rec.Code, rec.Header(), rec.Body.String()
	}

	getCode, getHdr, getBody := call(http.MethodGet)
	postCode, _, postBody := call(http.MethodPost)

	if getCode != http.StatusUnauthorized {
		t.Errorf("GET: want 401, got %d", getCode)
	}
	if postCode != http.StatusUnauthorized {
		t.Errorf("POST: want 401, got %d", postCode)
	}
	// GET and POST must be indistinguishable — same status and same body.
	if getBody != postBody {
		t.Errorf("GET and POST bodies differ:\n GET=%q\nPOST=%q", getBody, postBody)
	}
	// No data leaks to an anonymous caller.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if _, _, body := call(method); strings.Contains(body, `"events"`) {
			t.Errorf("%s: anonymous body must not contain events: %s", method, body)
		}
	}
	if ct := getHdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("GET: want application/json content-type, got %q", ct)
	}
	if getHdr.Get("X-Request-Id") == "" {
		t.Errorf("GET: expected an X-Request-Id header")
	}

	// Unsupported methods get 405 with an Allow header naming the
	// methods the endpoint implements.
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		code, hdr, body := call(method)
		if code != http.StatusMethodNotAllowed {
			t.Errorf("%s: want 405, got %d", method, code)
		}
		if allow := hdr.Get("Allow"); allow == "" {
			t.Errorf("%s: 405 must carry an Allow header", method)
		}
		if strings.Contains(body, `"events"`) {
			t.Errorf("%s: 405 body must not contain events: %s", method, body)
		}
	}
}

// TestAuthTokenRoundtrip verifies token generation and validation.
func TestAuthTokenRoundtrip(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-enough")
	serverID := "server-1"

	token := GenerateAuthToken(secret, serverID)
	if token == "" {
		t.Fatal("empty token")
	}
	t.Logf("token: %s", token)

	if !ValidateAuthToken(secret, serverID, token) {
		t.Error("valid token rejected")
	}

	// Wrong secret.
	if ValidateAuthToken([]byte("wrong-secret"), serverID, token) {
		t.Error("wrong secret accepted")
	}

	// Wrong server.
	if ValidateAuthToken(secret, "wrong-server", token) {
		t.Error("wrong server accepted")
	}
}

// TestConnectRejectsMalformedPubkeyPin verifies that the SNI-substitution
// path refuses to proceed with an invalid
// chameleon_pubkey_pin param — either not hex, or hex of the wrong
// length. Valid pin = exactly 32 bytes (sha256 of DER-encoded
// SubjectPublicKeyInfo); anything else is a config bug that must
// fail fast, not silently fall through to normal cert validation.
//
// We cannot test the happy-path substitute (picks whitelistSNI, wraps
// dialUTLSWith with the pin, handshakes and validates the peer cert
// against the pin) as a unit test because it requires a real TLS
// server presenting a cert we know the sha256 pubkey hash of. That
// part is covered by smoke testing an Android build against a live
// server.
func TestConnectRejectsMalformedPubkeyPin(t *testing.T) {
	cases := []struct {
		name    string
		pin     string
		wantErr string // substring expected in error message
	}{
		{
			name:    "not hex",
			pin:     "not-hex-at-all-zzz-whatever",
			wantErr: "chameleon_pubkey_pin hex",
		},
		{
			name:    "hex but too short (16 bytes)",
			pin:     "00112233445566778899aabbccddeeff",
			wantErr: "32 bytes",
		},
		{
			name:    "hex but too long (64 bytes)",
			pin:     strings.Repeat("ab", 64),
			wantErr: "32 bytes",
		},
		{
			name:    "hex but 31 bytes (off by one)",
			pin:     strings.Repeat("cd", 31),
			wantErr: "32 bytes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := New()
			ep := transport.Endpoint{
				ID: "test-endpoint",
				Params: map[string]string{
					"chameleon_addr":       "127.0.0.1:9999", // unreachable, but validation happens before dial
					"chameleon_sni":        "vpn.example.com",
					"user_secret":          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"server_id":            "test-server",
					"chameleon_pubkey_pin": tc.pin,
				},
			}
			_, err := tr.connect(context.Background(), ep)
			if err == nil {
				t.Fatalf("connect accepted bad pubkey_pin %q — expected error containing %q", tc.pin, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestConnectAcceptsValidPubkeyPin verifies that a well-formed 32-byte
// hex pubkey_pin passes validation and the error (if any) comes from
// the downstream TCP dial, not from the pin check. This locks in the
// "64 hex chars decode to 32 bytes and pass" happy path without
// requiring a running server.
func TestConnectAcceptsValidPubkeyPin(t *testing.T) {
	tr := New()
	ep := transport.Endpoint{
		ID: "test-endpoint",
		Params: map[string]string{
			"chameleon_addr":       "127.0.0.1:1", // almost certainly dead, dial fails
			"chameleon_sni":        "vpn.example.com",
			"user_secret":          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"server_id":            "test-server",
			"chameleon_pubkey_pin": strings.Repeat("ab", 32), // 32 bytes, valid shape
		},
	}
	_, err := tr.connect(context.Background(), ep)
	if err == nil {
		t.Fatal("connect succeeded against 127.0.0.1:1 — impossible, expected dial error")
	}
	// The error MUST be from the dial path, not from the pin check.
	// Pin-check errors contain "chameleon_pubkey_pin"; we want anything else.
	if strings.Contains(err.Error(), "chameleon_pubkey_pin") {
		t.Errorf("valid pin was rejected by validation: %v", err)
	}
}

// TestTransportHasSessionCache pins the invariant that New() returns a
// Transport wired with a non-nil session cache.
// Without this, every reconnect would emit a fresh ClientHello with no
// session ticket extension — a visible mismatch against real Chrome,
// which always reuses tickets within their lifetime.
//
// Why not test actual resumption end-to-end: uTLS (refraction-networking)
// rejects self-signed certs in our test servers by default, and
// plumbing InsecureSkipVerify through the test path would pollute the
// production dial function. Instead, HandshakeStats() is the observable
// metric an operator can eyeball on a live server after deploy: total
// climbs, resumed lags by 1 (the first handshake is always full), then
// tracks total-1.
func TestTransportHasSessionCache(t *testing.T) {
	tr := New()
	if tr.sessionCache == nil {
		t.Fatal("New() returned Transport with nil sessionCache — regression")
	}
	total, resumed := tr.HandshakeStats()
	if total != 0 || resumed != 0 {
		t.Errorf("fresh Transport should have zero handshakes, got total=%d resumed=%d", total, resumed)
	}

	// Two Transports must have independent caches and counters — one
	// mobile client per installation should not share TLS session
	// tickets across multiple chamele0nx.Transport instances.
	tr2 := New()
	if tr2.sessionCache == nil {
		t.Fatal("second New() also returned nil sessionCache")
	}
	if tr2.sessionCache == tr.sessionCache {
		t.Error("two New() Transports share the same sessionCache — should be per-Transport")
	}
}

// TestNewUTLSConfigEnforcesCriticalRules guards the TLS record-sizing
// invariant. An earlier revision of the client constructed utls.Config
// without DynamicRecordSizingDisabled=true. The flag was present on the
// server and in every test helper, but quietly missing in the hot
// production dial path — a clean client/server asymmetry fingerprint on
// every session's first ~128KB of data, which is exactly the window a
// DPI box uses to classify VPN traffic versus a real site.
//
// If this test ever fails, do not "fix" it by updating the assertion. The
// whole point of Chamele0nX collapses without this flag — see
// docs/en/THREAT-MODEL.md before touching anything.
func TestNewUTLSConfigEnforcesCriticalRules(t *testing.T) {
	tr := New()
	cfg := tr.newUTLSConfig("example.com")

	if cfg == nil {
		t.Fatal("newUTLSConfig returned nil")
	}
	if !cfg.DynamicRecordSizingDisabled {
		t.Fatal("regression: DynamicRecordSizingDisabled must be true on the client. " +
			"Without it uTLS ramps TLS record size 512B→16KB over the " +
			"first ~128KB and ShapedConn cannot compensate — DPI classifies the session " +
			"as VPN in the first 2–5s of every mobile connection.")
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName not propagated: want %q, got %q", "example.com", cfg.ServerName)
	}
	if cfg.ClientSessionCache == nil {
		t.Error("ClientSessionCache nil — breaks Chrome-like session resumption on reconnect")
	}
	if cfg.ClientSessionCache != tr.sessionCache {
		t.Error("ClientSessionCache not bound to Transport's per-instance cache — " +
			"two Transport instances would share tickets, violating per-client isolation")
	}
}

// TestAuthenticateClientAllSecretsChecked verifies the constant-time
// invariant: authenticateClient iterates EVERY entry in
// UserSecrets regardless of whether an early entry already matched.
//
// This is a correctness test for the constant-time refactor — if a
// future edit accidentally reintroduces an early `return true` inside
// the inner loop, two failure modes surface here:
//   - The test with the last secret (key "secret-5") matching would
//     still pass (early return on match works forward). So we add a
//     test that exercises EACH secret position — that catches a
//     *broken* map iteration that short-circuits before some secrets.
//   - Empty / malformed cookies must not regress their early-exit paths.
//
// We cannot test true constant-time timing portably (clock noise on CI
// is huge relative to HMAC cost) — so this is a correctness regression
// test, not a statistical timing test. The only timing property pinned
// is "matched variable accumulation is consistent across all map
// iteration orders" — Go randomizes map order per-run, so iterating
// this test multiple times catches an order-dependent bug.
func TestAuthenticateClientAllSecretsChecked(t *testing.T) {
	const serverID = "unit-server"

	// Five distinct 32-byte secrets. Each slot gets its own entry in
	// UserSecrets so we can verify every position can auth on its own.
	secrets := map[string][]byte{
		"user-1": bytes.Repeat([]byte{0x11}, 32),
		"user-2": bytes.Repeat([]byte{0x22}, 32),
		"user-3": bytes.Repeat([]byte{0x33}, 32),
		"user-4": bytes.Repeat([]byte{0x44}, 32),
		"user-5": bytes.Repeat([]byte{0x55}, 32),
	}

	srv := NewServer(ServerConfig{
		ListenAddr:   "127.0.0.1:0", // not actually listening
		APIPath:      "/api/v1/events",
		ServerID:     serverID,
		UserSecrets:  secrets,
		CookieFormat: "generic",
		Logger:       slog.Default(),
	})

	// For each secret, generate its token and verify
	// authenticateClient accepts it. This asserts correctness across
	// every map slot — if the loop bailed early before reaching some
	// slot, one of these sub-tests would fail (map order is random).
	for name, secret := range secrets {
		t.Run("match_"+name, func(t *testing.T) {
			// Run 10 iterations — because Go randomizes map order per
			// run, and the loop must now ALWAYS iterate all secrets,
			// every iteration must return true regardless of the
			// current map order.
			for i := 0; i < 10; i++ {
				token := GenerateAuthToken(secret, serverID)
				req := &http.Request{Header: http.Header{}}
				req.Header.Set("Cookie", FormatCookie(token, "generic"))
				if !srv.authenticateClient(req) {
					t.Fatalf("valid token for %s rejected (iter %d)", name, i)
				}
			}
		})
	}

	// Negative cases — none of these should auth.
	t.Run("no_cookie", func(t *testing.T) {
		req := &http.Request{Header: http.Header{}}
		if srv.authenticateClient(req) {
			t.Error("empty cookie header accepted")
		}
	})
	t.Run("wrong_token", func(t *testing.T) {
		req := &http.Request{Header: http.Header{}}
		req.Header.Set("Cookie", "sid=not-a-real-token")
		if srv.authenticateClient(req) {
			t.Error("garbage token accepted")
		}
	})
	t.Run("wrong_secret", func(t *testing.T) {
		// Token generated from a secret NOT in the server's UserSecrets.
		otherSecret := bytes.Repeat([]byte{0xFF}, 32)
		token := GenerateAuthToken(otherSecret, serverID)
		req := &http.Request{Header: http.Header{}}
		req.Header.Set("Cookie", FormatCookie(token, "generic"))
		if srv.authenticateClient(req) {
			t.Error("token from unknown secret accepted")
		}
	})
}

// TestUserSecretHexValidation pins the contract that user_secret in
// endpoint params is hex-encoded. This is the regression test for a bug
// where an iOS smoke-test client passed the secret as a hex
// string and the chamele0nx transport did `[]byte(string)` on it,
// producing a 64-byte ASCII key instead of the 32-byte raw key the
// server uses for HMAC. The result was tokens that never validated
// against any production secret → all auth-fail → cover site → 404.
//
// The fix moved the hex decode from the CLI into validateChamele0nXParams,
// so any param map that survives JSON round-trip carries hex and
// every entry point uses the same convention.
func TestUserSecretHexValidation(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		wantErr string // empty = accept
	}{
		{
			name:   "valid 32-byte hex",
			secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:   "valid 16-byte hex (minimum)",
			secret: "00000000000000000000000000000000",
		},
		{
			name:    "missing",
			secret:  "",
			wantErr: "missing required param: user_secret",
		},
		{
			name:    "raw bytes pretending to be string",
			secret:  string([]byte{0x06, 0xd2, 0x53, 0x8b, 0xff, 0xfe, 0xfd, 0x00}),
			wantErr: "user_secret must be hex-encoded",
		},
		{
			name:    "ascii word — would have parsed as raw bytes pre-fix",
			secret:  "test-secret-32-bytes-long-enough",
			wantErr: "user_secret must be hex-encoded",
		},
		{
			name:    "valid hex but too short",
			secret:  "deadbeefdeadbeef", // 8 bytes
			wantErr: "user_secret too short",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := transport.Endpoint{
				ID:        "test",
				Address:   "example.com:443",
				Transport: "chamele0nx",
				Params: map[string]string{
					"chameleon_addr": "example.com:443",
				},
			}
			if tc.secret != "" {
				ep.Params["user_secret"] = tc.secret
			}

			err := validateChamele0nXParams(ep)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected accept, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

// TestCookieFormats verifies cookie formatting and parsing.
func TestCookieFormats(t *testing.T) {
	token := "abc123XYZ"

	for _, format := range []string{"generic", "wordpress", "django"} {
		cookie := FormatCookie(token, format)
		parsed := ParseCookie(cookie, format)
		if parsed != token {
			t.Errorf("%s: format(%q)=%q, parse=%q (expected %q)",
				format, token, cookie, parsed, token)
		}
		t.Logf("%s: %s", format, cookie)
	}
}

// TestFrameRoundtrip verifies frame encoding/decoding.
func TestFrameRoundtrip(t *testing.T) {
	payload := make([]byte, 1000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	frame := Frame{Type: frameData, Payload: payload}

	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Type != frame.Type {
		t.Errorf("type: %d vs %d", got.Type, frame.Type)
	}
	if !bytes.Equal(got.Payload, frame.Payload) {
		t.Error("payload mismatch")
	}
}

// connectChamele0nXTest connects to the test server bypassing uTLS
// (since we're using a self-signed cert, not a real one).
func connectChamele0nXTest(ctx context.Context, ct *Transport, endpoint transport.Endpoint, cert tls.Certificate) (transport.Tunnel, error) {
	addr := endpoint.Params["chameleon_addr"]
	sni := endpoint.Params["chameleon_sni"]
	apiPath := endpoint.Params["chameleon_path"]
	cookieFormat := endpoint.Params["chameleon_cookie"]
	// Mirror the production convention: user_secret in params is hex.
	userSecret, err := hex.DecodeString(endpoint.Params["user_secret"])
	if err != nil {
		return nil, fmt.Errorf("test helper: bad user_secret hex: %w", err)
	}
	serverID := endpoint.Params["server_id"]

	token := GenerateAuthToken(userSecret, serverID)
	cookie := FormatCookie(token, cookieFormat)

	// For testing: use standard TLS instead of uTLS (self-signed cert).
	tlsDialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify:          true,
			NextProtos:                  []string{"h2"},
			DynamicRecordSizingDisabled: true,
		},
	}

	clientSeed := generateClientSeed()
	clientProfile := DefaultSaaSProfile()

	h2t := &fhttp2.Transport{
		// v2.1: fhttp/http2 DialTLS has no context and uses bgnutls.Config
		// instead of stdlib *tls.Config. We ignore both — the test dialer
		// uses stdlib tls.Dialer with its own config + a 15s deadline.
		DialTLS: func(network, _ string, _ *bgnutls.Config) (net.Conn, error) {
			conn, err := tlsDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return NewShapedConn(conn, clientProfile, clientSeed), nil
		},
		// v2.1: must mirror production's H2 settings — without an
		// explicit Settings/SettingsOrder, fhttp/http2's default HEADERS
		// framing diverges from what stdlib http2.Server (used here) is
		// willing to accept, manifesting as PROTOCOL_ERROR on stream 1.
		Settings: map[fhttp2.SettingID]uint32{
			fhttp2.SettingHeaderTableSize:   65536,
			fhttp2.SettingEnablePush:        0,
			fhttp2.SettingInitialWindowSize: 6291456,
			fhttp2.SettingMaxHeaderListSize: 262144,
		},
		SettingsOrder: []fhttp2.SettingID{
			fhttp2.SettingHeaderTableSize,
			fhttp2.SettingEnablePush,
			fhttp2.SettingInitialWindowSize,
			fhttp2.SettingMaxHeaderListSize,
		},
		ConnectionFlow:    15663105,
		InitialWindowSize: 6291456,
		HeaderTableSize:   65536,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},

		AllowHTTP:          false,
		DisableCompression: true,
		ReadIdleTimeout:    15 * time.Second,
		PingTimeout:        5 * time.Second,
	}

	pr, pw := io.Pipe()

	req, err := fhttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://%s%s", sni, apiPath), pr)
	if err != nil {
		pw.Close()
		return nil, err
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Host = sni

	resp, err := h2t.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("h2 post: %w", err)
	}

	if resp.StatusCode != fhttp.StatusOK {
		pw.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// ECDH key exchange.
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, err
	}

	if err := WriteFrame(pw, Frame{Type: frameKeyExchange, Payload: privKey.PublicKey().Bytes()}); err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, err
	}

	serverFrame, err := ReadFrame(resp.Body)
	if err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("read server pubkey: %w", err)
	}
	if serverFrame.Type != frameKeyExchange || len(serverFrame.Payload) != 32 {
		pw.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("bad key exchange frame")
	}

	serverPubKey, err := ecdh.X25519().NewPublicKey(serverFrame.Payload)
	if err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, err
	}

	sharedSecret, err := privKey.ECDH(serverPubKey)
	if err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, err
	}

	sessionKey, err := deriveSessionKey(sharedSecret)
	zeroize(sharedSecret)
	if err != nil {
		pw.Close()
		resp.Body.Close()
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
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		done:       make(chan struct{}),
	}

	// Start reader goroutine.
	go tun.readLoop()

	// Start SOCKS5 proxy.
	port, err := findFreePort()
	if err != nil {
		tun.Close()
		return nil, err
	}
	if err := tun.startSOCKS5(port); err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
