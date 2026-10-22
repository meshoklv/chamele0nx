package chamele0nx

import (
	"strings"
	"testing"
)

// TestPickUserAgentDeterministic verifies that the same seed always
// returns the same UA string. Required so the header is stable for the
// lifetime of one connection.
func TestPickUserAgentDeterministic(t *testing.T) {
	for _, seed := range []uint64{1, 0xFF, 0xDEADBEEF, 0xCAFEBABE0123456} {
		a := pickUserAgent(seed)
		b := pickUserAgent(seed)
		if a != b {
			t.Errorf("seed=0x%x: pickUserAgent not deterministic: %q vs %q", seed, a, b)
		}
	}
}

// TestPickUserAgentDistribution verifies that the pool is actually
// reachable — running through 10000 random seeds, every entry should
// be picked at least once. Otherwise we have a buggy hash collapsing
// the pool to a subset.
func TestPickUserAgentDistribution(t *testing.T) {
	seen := make(map[string]int)
	for seed := uint64(1); seed <= 10000; seed++ {
		seen[pickUserAgent(seed)]++
	}
	if len(seen) != len(userAgentPool) {
		t.Errorf("only %d/%d UAs reached over 10000 seeds — distribution bug", len(seen), len(userAgentPool))
	}
	// Each entry should appear at least 100 times in 10k seeds (a
	// collapsed distribution would have some at single digits or 0).
	for ua, count := range seen {
		if count < 100 {
			t.Errorf("UA %q only seen %d times in 10000 seeds — distribution skew", ua, count)
		}
	}
}

// TestPickUserAgentZeroSeed verifies that seed=0 returns a sane default
// (not empty, not garbage). Used by tests and as a fallback when seed
// generation hasn't run.
func TestPickUserAgentZeroSeed(t *testing.T) {
	ua := pickUserAgent(0)
	if ua == "" {
		t.Fatal("pickUserAgent(0) returned empty string")
	}
	if !strings.Contains(ua, "Mozilla/5.0") {
		t.Errorf("pickUserAgent(0) doesn't look like a UA: %q", ua)
	}
}

// TestUserAgentPoolShape verifies the pool itself is non-empty and
// every entry is a plausible UA (starts with Mozilla/5.0 — every modern
// browser does this for backward compat).
func TestUserAgentPoolShape(t *testing.T) {
	if len(userAgentPool) == 0 {
		t.Fatal("userAgentPool is empty")
	}
	for i, ua := range userAgentPool {
		if !strings.HasPrefix(ua, "Mozilla/5.0") {
			t.Errorf("pool[%d] doesn't start with Mozilla/5.0: %q", i, ua)
		}
		if len(ua) < 50 {
			t.Errorf("pool[%d] suspiciously short (%d chars): %q", i, len(ua), ua)
		}
	}
}

// TestUserAgentPoolChromium enforces the
// invariant that every UA in the pool is Chromium-based, so its real-
// browser H2 SETTINGS fingerprint matches what the HTTP/2 client emits in
// chamele0nx.go connect() (Chrome 146 profile).
//
// An active prober with a valid auth token would catch a UA/H2 mismatch
// in one request: receive the ClientHello + H2 SETTINGS, then compare
// to the advertised browser. Firefox-UA + Chrome-SETTINGS = instant flag.
// Firefox, Safari and iOS-Chrome entries were removed from the pool for
// exactly this reason; this test locks that restriction in so future
// edits cannot silently reintroduce them.
//
// Requirements every entry must satisfy:
//  1. Contains the literal substring "Chrome/146" — asserts Chromium
//     engine matching our H2 profile.
//  2. Does NOT contain "Firefox/", "CriOS/", or "Version/26.0" — the
//     three stop-markers of Firefox / iOS Chrome / Safari, respectively.
//
// If the pool ever needs to support non-Chromium UAs, the HTTP/2 client would
// have to be taught per-UA H2 fingerprint profiles AND pickUserAgent
// would need to expose its choice back to the H2 config path.
// Both are explicitly out of scope; until then this test stays.
func TestUserAgentPoolChromium(t *testing.T) {
	for i, ua := range userAgentPool {
		if !strings.Contains(ua, "Chrome/146") {
			t.Errorf("pool[%d] missing Chrome/146 marker (H2 fingerprint mismatch risk): %q", i, ua)
		}
		for _, banned := range []string{"Firefox/", "CriOS/", "Version/26.0"} {
			if strings.Contains(ua, banned) {
				t.Errorf("pool[%d] contains banned marker %q (non-Chromium H2 stack): %q", i, banned, ua)
			}
		}
	}
}
