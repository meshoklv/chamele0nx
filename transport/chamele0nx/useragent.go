package chamele0nx

// User-Agent pool for the Chamele0nX HTTP/2 client.
//
// This pool closes the "every Chamele0nX user shares the same User-Agent
// string" weakness. The header is not visible to passive DPI (it sits
// inside TLS), but it is visible to any active probe holding a valid
// auth token, and a single fixed value would let an observer group all
// Chamele0nX traffic by one fingerprint. The fix is small: a pool of
// currently-realistic User-Agents, selected deterministically per
// connection from clientSeed.
//
// ===== The pool is restricted to Chromium-compatible User-Agents =====
//
// The client sends HTTP/2 via fhttp/http2 configured to emit the Chrome 146
// H2 fingerprint (SETTINGS, window size, pseudo-header order — see
// chamele0nx.go connect()). A UA advertising Firefox or Safari in the header
// combined with Chrome's H2 SETTINGS is a *visible mismatch* to any active
// prober with a valid auth token: one POST, compare ClientHello to the
// advertised browser, catch. Passive DPI cannot see it (UA is inside TLS),
// but that hardening is defense-in-depth specifically against active probes.
//
// So the pool is restricted to UAs whose real-browser H2 stack matches ours:
//   - Chrome Win/Mac/Linux/Android (same Chromium engine → same H2 SETTINGS)
//   - Edge Windows (also Chromium-based since 2020, same H2 profile; the
//     Edge UA literally contains "Chrome/146.0.0.0 ... Edg/147.x" as an
//     explicit marker of its Chromium origin)
//
// Deliberately excluded:
//   - Firefox 149 — real Gecko stack, different H2 SETTINGS
//   - Safari 26 desktop & mobile — WebKit, different H2 SETTINGS
//   - CriOS 147 iPhone/iPad — iOS Chrome is WebKit-backed (Apple policy),
//     NOT a real Chromium H2 stack
//
// MUST be refreshed when Chrome's major version rolls. A version drift of
// more than 6 months turns the pool itself into a fingerprint signal — a
// real Chrome user is on the latest stable release, not one from a year ago.

// userAgentPool is the rotation set. Every entry MUST be a Chromium-based
// browser so its real-browser H2 fingerprint matches what fhttp/http2 emits
// (Chrome 146). Selection is by hash modulo length (pickUserAgent), not by
// index, so order doesn't matter.
var userAgentPool = []string{
	// Chrome 146 desktop — Windows (most common single UA on the web).
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
	// Chrome 146 desktop — macOS (Intel build, frozen by Google).
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
	// Chrome 146 desktop — Linux.
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
	// Chrome 146 mobile — Android (frozen "K" device label).
	"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.178 Mobile Safari/537.36",
	// Edge 147 desktop — Windows. Chromium-based, same H2 stack as Chrome.
	// The UA literally contains "Chrome/146.0.0.0" followed by "Edg/147" —
	// that Chrome marker is how we assert the H2 match.
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/147.0.3912.60",
}

// pickUserAgent returns a UA string deterministic-ally selected from
// userAgentPool based on the clientSeed. Same seed → same UA, so the
// header is stable for the lifetime of the connection (no mid-session
// flip, which would itself be a fingerprint signal).
//
// There is no special case for seed 0: the seed is mixed before it is
// reduced, so every seed including zero lands somewhere in the pool.
//
// Every returned UA is guaranteed to be Chromium-based (see pool comment
// above) — the TestUserAgentPoolChromium test enforces this invariant.
func pickUserAgent(seed uint64) string {
	if len(userAgentPool) == 0 {
		// Defensive fallback. Should never trigger — pool is hard-coded.
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	}
	// Mix the seed once to scramble locality (consecutive seeds shouldn't
	// pick consecutive pool entries).
	mixed := mixSeed(seed, 42)
	return userAgentPool[mixed%uint64(len(userAgentPool))]
}
