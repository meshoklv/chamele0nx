package chamele0nx

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDefaultCoverHasNoSharedConstants guards the fingerprinting fix in
// newDefaultCover. An earlier revision answered /api/v1/health with a
// hardcoded version and an uptime of unix%86400 — the same two values on
// every deployment on earth at any instant. That was a zero-false-positive
// scan signature: one request per address and a censor has the whole fleet.
//
// The property that matters is not "the numbers look plausible" but "two
// independently started servers do not agree", so that is what is asserted.
func TestDefaultCoverHasNoSharedConstants(t *testing.T) {
	health := func(c *defaultCover) string {
		rec := httptest.NewRecorder()
		c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("health returned %d, want 200", rec.Code)
		}
		return rec.Body.String()
	}

	// The literal that used to be compiled into every binary must be gone.
	if body := health(newDefaultCover()); strings.Contains(body, `"version":"2.1.0"`) {
		t.Fatalf("health response still carries the hardcoded version: %s", body)
	}

	// The reported version must vary between servers. Compare the version
	// alone, not the whole body: the uptime varies by itself, so a body
	// comparison would pass even with the version pinned back to a constant.
	versions := make(map[string]struct{})
	const samples = 64
	for i := 0; i < samples; i++ {
		versions[newDefaultCover().version] = struct{}{}
	}
	if len(versions) < samples/4 {
		t.Errorf("only %d distinct versions across %d servers — the version is close to a constant",
			len(versions), samples)
	}

	// Uptime must be a real elapsed time for this process, not a global
	// clock reading. Two covers started a moment apart therefore report
	// values that are unrelated to the wall clock's seconds-since-midnight.
	c := newDefaultCover()
	if c.startedAt.After(time.Now()) {
		t.Error("cover reports a start time in the future")
	}
	// The start time is drawn from a range that includes zero, so a single
	// cover may legitimately report a very small uptime. What must not
	// happen is every cover reporting the same one.
	uptimes := make(map[int64]struct{})
	for i := 0; i < 64; i++ {
		uptimes[int64(time.Since(newDefaultCover().startedAt).Seconds())] = struct{}{}
	}
	if len(uptimes) < 16 {
		t.Errorf("only %d distinct uptimes across 64 servers — uptime is close to a constant", len(uptimes))
	}
}

// TestDefaultCoverPathsUnchanged pins the behaviour the active-probe defence
// depends on: the cover answers its own endpoints and 404s everything else.
func TestDefaultCoverPathsUnchanged(t *testing.T) {
	c := newDefaultCover()
	for _, tc := range []struct {
		path string
		code int
		want string
	}{
		{"/api/v1/health", http.StatusOK, `"status":"ok"`},
		{"/api/v1/events", http.StatusOK, `"events":[]`},
		{"/nothing/here", http.StatusNotFound, `"error":"not_found"`},
	} {
		rec := httptest.NewRecorder()
		c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.code {
			t.Errorf("%s returned %d, want %d", tc.path, rec.Code, tc.code)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s body %q does not contain %q", tc.path, rec.Body.String(), tc.want)
		}
		if rec.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s did not set a request id", tc.path)
		}
	}
}

// TestValidateAuthTokenRejectsWrongLength covers the cheap precheck that
// keeps a flood of junk candidates from costing a digest each.
func TestValidateAuthTokenRejectsWrongLength(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	const serverID = "unit-server"

	valid := GenerateAuthToken(secret, serverID)
	if len(valid) != authTokenLen {
		t.Fatalf("generated token is %d chars, expected %d", len(valid), authTokenLen)
	}
	if !ValidateAuthToken(secret, serverID, valid) {
		t.Fatal("a freshly generated token was rejected")
	}

	for _, bad := range []string{"", "x", valid[:len(valid)-1], valid + "x", strings.Repeat("A", 1024)} {
		if ValidateAuthToken(secret, serverID, bad) {
			t.Errorf("token of length %d accepted", len(bad))
		}
	}
}

// TestAuthenticateClientBoundsUnauthenticatedWork is the regression test for
// the CPU-exhaustion path: the Cookie header is attacker-supplied, arrives
// before any authentication has succeeded, and the secret loop deliberately
// does not short-circuit. A header packed with cookie segments must therefore
// not buy an unbounded number of HMACs.
//
// The load-bearing assertions are structural — a valid token past the cap must
// not authenticate — because with the caps in place the number of candidates
// examined cannot exceed maxAuthCandidates regardless of header size. The
// wall-clock check is only a smoke test, with a margin wide enough that a
// loaded machine cannot make it flaky.
func TestAuthenticateClientBoundsUnauthenticatedWork(t *testing.T) {
	const serverID = "unit-server"
	secrets := map[string][]byte{
		"user-1": bytes.Repeat([]byte{0x11}, 32),
		"user-2": bytes.Repeat([]byte{0x22}, 32),
	}
	srv := NewServer(ServerConfig{
		ListenAddr:   "127.0.0.1:0", // not actually listening
		APIPath:      "/api/v1/events",
		ServerID:     serverID,
		UserSecrets:  secrets,
		CookieFormat: "generic",
		Logger:       slog.Default(),
	})

	// A header full of well-formed, wrong tokens: the most expensive shape
	// an attacker can send, since each one survives the length precheck.
	junk := strings.Repeat("A", authTokenLen)
	flood := strings.TrimSuffix(strings.Repeat("sid="+junk+"; ", 200000), "; ")

	req := &http.Request{Header: http.Header{}}
	req.Header.Set("Cookie", flood)

	start := time.Now()
	if srv.authenticateClient(req) {
		t.Fatal("a header of junk tokens authenticated")
	}
	elapsed := time.Since(start)

	// maxAuthCandidates candidates x 2 secrets x 2 buckets is a few dozen
	// HMAC-SHA256 over ~30 bytes: microseconds. Without the caps the same
	// header costs 800 000 digests, which is seconds even on fast hardware.
	// The timing bound is a smoke check with an enormous margin; the
	// assertions below it are the ones that actually pin the behaviour.
	if elapsed > 2*time.Second {
		t.Errorf("a 200 000-segment cookie header took %s — the work is not bounded", elapsed)
	}

	// A valid token still authenticates when it appears within the caps.
	req = &http.Request{Header: http.Header{}}
	req.Header.Set("Cookie", FormatCookie(GenerateAuthToken(secrets["user-2"], serverID), "generic"))
	if !srv.authenticateClient(req) {
		t.Error("a valid token was rejected after the bounds were added")
	}

	// A valid token buried past the cap is not reachable. That is the
	// deliberate trade: no real client sends its session cookie in
	// position 5 000, and the alternative is unbounded work.
	buried := strings.Repeat("sid="+junk+"; ", maxCookieParts+maxAuthCandidates+10) +
		FormatCookie(GenerateAuthToken(secrets["user-1"], serverID), "generic")
	req = &http.Request{Header: http.Header{}}
	req.Header.Set("Cookie", buried)
	if srv.authenticateClient(req) {
		t.Error("a token beyond the scan cap authenticated — the cap is not being applied")
	}
}
