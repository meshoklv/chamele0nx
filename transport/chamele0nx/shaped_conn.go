package chamele0nx

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ShapedConn wraps a net.Conn (TLS connection) and reshapes Write calls
// to produce TLS records whose sizes match a site traffic profile.
//
// The inner connection MUST have DynamicRecordSizingDisabled = true,
// ensuring each Write(N) produces exactly one TLS record with N-byte payload.
//
// When HTTP/2 writes large DATA frames, ShapedConn splits them into
// multiple writes of varying sizes sampled from the profile's record
// size distribution with per-client jitter. This prevents the uniform
// ~16KB TLS records that ML-based DPI uses to identify VPN tunnels.
//
// Small writes (< minShapingThreshold) pass through unchanged — these
// correspond to HTTP/2 control frames which are expected at their natural sizes.
//
// v2 adds burst-pause timing injection: after every RecordsPerBurst records
// the shaper sleeps for an InterBurstPause-sampled duration (capped at
// maxBurstPauseInWrite unless profile.BypassPauseCap is true). This closes
// the timing-entropy hole left by v1, where records streamed back-to-back
// without any inter-burst gap and trivially failed ML-DPI timing tests.
//
// Thread-safe: concurrent Write calls are serialized via mutex.
type ShapedConn struct {
	inner   net.Conn
	profile *SiteProfile
	seed    uint64 // per-client jitter seed (FOCI 2024)

	writeMu sync.Mutex
	counter atomic.Uint64 // monotonic counter for per-record seed derivation

	// armed gates whether Write shapes at all. While false, every Write
	// passes straight through to the inner connection unshaped. The
	// server starts a connection un-armed and only arms it once the
	// tunnel handler has authenticated the client, so an unauthenticated
	// probe fetching the cover site sees ordinary site traffic, not the
	// shaping envelope. Connections built by NewShapedConn (the client,
	// and the shaping unit tests) start armed.
	armed atomic.Bool

	// v2 burst state — all access guarded by writeMu.
	//
	// recordsInBurst counts records emitted in the current burst window.
	// burstTarget is the target size of the current burst, sampled from
	// profile.BurstPattern.RecordsPerBurst at the start of each burst.
	// lastWriteTime is the wall-clock time of the most recent inner.Write,
	// used for natural-gap deduction in maybeBurstPause.
	recordsInBurst int
	burstTarget    int
	lastWriteTime  time.Time
}

// minShapingThreshold: writes smaller than this pass through unshaped.
// HTTP/2 control frames (SETTINGS=45B, WINDOW_UPDATE=13B, PING=17B,
// HEADERS=100-500B) are below this and should appear at their natural sizes.
const minShapingThreshold = 512

// maxBurstPauseInWrite caps how long an inline burst pause may block Write.
//
// Rationale: an inline time.Sleep inside ShapedConn.Write holds writeMu,
// which blocks every HTTP/2 stream sharing this connection for the full
// pause duration. A 30-second profile pause would stall every concurrent
// SOCKS5 stream for 30 seconds, breaking any interactive use.
//
// 250ms is the empirical sweet spot: long enough to inject timing entropy
// that defeats ML-DPI "back-to-back records" detection, short enough that
// no user-visible latency spikes appear on regular browsing/chat traffic.
//
// This is the upper BOUND of the pause distribution, not a clamp applied
// after sampling. nextBurstPause truncates the sampling range to this
// value first and then draws, so pauses spread smoothly up to it. An
// earlier revision drew from the full profile range and clamped the
// result down to this cap, which collected every over-cap draw onto this
// one exact value — a point mass at 250ms that no real site produces.
//
// Profiles that need longer pauses (Stealth mode, explicit low-bandwidth
// trading) must set BypassPauseCap = true to opt out of the bound.
const maxBurstPauseInWrite = 250 * time.Millisecond

// defaultBurstTarget is the initial RecordsPerBurst fallback when the
// profile has a zero/invalid range.
const defaultBurstTarget = 10

// NewShapedConn creates a connection wrapper that shapes TLS records.
// conn must be a TLS connection with DynamicRecordSizingDisabled = true.
// profile defines the target record size distribution.
// clientSeed provides per-client jitter to prevent cross-client correlation.
func NewShapedConn(conn net.Conn, profile *SiteProfile, clientSeed uint64) *ShapedConn {
	sc := &ShapedConn{
		inner:   conn,
		profile: profile,
		seed:    clientSeed,
	}
	// Shaped from the first write. The client is always the
	// authenticated tunnel, so there is nothing to gate on its side.
	sc.armed.Store(true)
	return sc
}

// newGatedShapedConn is like NewShapedConn but starts un-armed: writes
// pass through untouched until Arm is called. The server uses this so an
// unauthenticated request (an active probe fetching the cover site)
// never receives shaped output. Shaping switches on only after the
// tunnel handler authenticates the client.
func newGatedShapedConn(conn net.Conn, profile *SiteProfile, clientSeed uint64) *ShapedConn {
	return &ShapedConn{
		inner:   conn,
		profile: profile,
		seed:    clientSeed,
	}
}

// Arm turns shaping on. Idempotent. Called by the server once a
// connection is confirmed to carry an authenticated tunnel.
func (sc *ShapedConn) Arm() { sc.armed.Store(true) }

// Write reshapes large writes into multiple TLS records matching the profile.
// Each chunk written to the inner TLS conn becomes one TLS record
// (guaranteed by DynamicRecordSizingDisabled = true).
//
// Data integrity: TLS is a stream protocol — splitting writes differently
// does not affect HTTP/2 framing on the receiver side. The receiver's TLS
// layer reassembles records into a byte stream before HTTP/2 reads from it.
//
// v2: between bursts (RecordsPerBurst records) the shaper injects a
// sampled InterBurstPause via time.Sleep. See maybeBurstPause for the
// natural-gap-deduction logic that keeps idle connections un-blocked.
func (sc *ShapedConn) Write(p []byte) (int, error) {
	// nil profile → pass-through without locking overhead.
	// Un-armed → pass-through too: shaping has not been switched on for
	// this connection yet (unauthenticated traffic on the server).
	if sc.profile == nil || !sc.armed.Load() {
		return sc.inner.Write(p)
	}

	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	// Small writes pass through unshaped (HTTP/2 control frames).
	// They do NOT advance the burst counter — control frames shouldn't
	// consume our synthetic "page load" budget.
	if len(p) < minShapingThreshold {
		return sc.inner.Write(p)
	}

	written := 0
	for written < len(p) {
		// v2: check if a burst pause should be injected before the next
		// record. On the very first call this just picks an initial burst
		// target and returns without sleeping.
		sc.maybeBurstPause()

		target := sc.nextRecordSize()

		chunk := target
		if chunk > len(p)-written {
			chunk = len(p) - written
		}

		n, err := sc.inner.Write(p[written : written+chunk])
		written += n
		sc.recordsInBurst++
		sc.lastWriteTime = time.Now()
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// maybeBurstPause is the v2 timing-injection hook. Called before every
// shaped record write. Behavior:
//
//  1. If no burst target has been picked yet (first ever write), pick one
//     and return without sleeping.
//  2. If the current burst is not yet full (recordsInBurst < burstTarget),
//     return without sleeping.
//  3. Otherwise the burst is complete: sample an InterBurstPause duration,
//     subtract any time already elapsed since lastWriteTime (natural-gap
//     deduction), and sleep for the remainder. Then reset burst state.
//
// Natural-gap deduction is important: if the HTTP/2 writer was already
// idle for longer than the sampled pause, we've already paid the timing
// cost "for free" and don't need to block further. This makes the shaper
// invisible on chat / tab-switching traffic patterns and only bites when
// an application is actually streaming bulk data.
//
// MUST be called with writeMu held.
func (sc *ShapedConn) maybeBurstPause() {
	if sc.burstTarget == 0 {
		sc.pickBurstTarget()
		return
	}
	if sc.recordsInBurst < sc.burstTarget {
		return
	}

	pause := sc.nextBurstPause()
	if pause > 0 && !sc.lastWriteTime.IsZero() {
		elapsed := time.Since(sc.lastWriteTime)
		if elapsed < pause {
			time.Sleep(pause - elapsed)
		}
	}
	sc.recordsInBurst = 0
	sc.pickBurstTarget()
}

// pickBurstTarget samples the next burst size from the profile.
// Falls back to defaultBurstTarget on bad/missing profile data.
// MUST be called with writeMu held.
func (sc *ShapedConn) pickBurstTarget() {
	sc.recordsInBurst = 0
	if sc.profile == nil {
		sc.burstTarget = defaultBurstTarget
		return
	}
	rng := sc.profile.BurstPattern.RecordsPerBurst
	t, err := cryptoRandRange(rng.Min, rng.Max)
	if err != nil || t <= 0 {
		t = defaultBurstTarget
	}
	sc.burstTarget = t
}

// nextBurstPause samples the next inter-burst pause duration from the
// profile. Returns 0 if the profile has no burst-pause configured.
//
// The cap (maxBurstPauseInWrite, unless BypassPauseCap is set) truncates
// the sampling range BEFORE a value is drawn — it is an upper bound on
// the distribution, not a post-hoc clamp. Clamping after sampling piles
// every over-cap draw onto one exact value, producing a point mass at
// the cap that no real site's inter-record timing shows. Truncating the
// range first spreads the draws smoothly up to the bound.
//
// The draw itself is log-uniform rather than uniform: real inter-request
// gaps are heavy-tailed (most gaps short, a thin tail of long ones), so a
// flat uniform spread is itself distinguishable. Log-uniform weights
// short pauses more heavily and tapers toward the bound, matching that
// shape while staying strictly inside [min, effectiveMax].
func (sc *ShapedConn) nextBurstPause() time.Duration {
	if sc.profile == nil {
		return 0
	}
	bp := sc.profile.BurstPattern.InterBurstPause
	if bp.Max <= 0 {
		return 0
	}

	min, max := bp.Min, bp.Max
	if !sc.profile.BypassPauseCap && max > maxBurstPauseInWrite {
		max = maxBurstPauseInWrite
	}
	// The cap can fall below the profile's own minimum (a profile that
	// asks for pauses longer than the inline cap allows). There is no
	// range left to sample; return the bound.
	if min >= max {
		return max
	}

	d, err := cryptoRandLogUniform(min, max)
	if err != nil {
		return 0
	}
	return d
}

// nextRecordSize samples a record size from the profile distribution with
// per-client jitter (±RecordJitterPercent, per the FOCI 2024 cross-client
// correlation defence).
func (sc *ShapedConn) nextRecordSize() int {
	n := sc.counter.Add(1)

	size, err := sc.profile.sampleRecordSize()
	if err != nil {
		return 4096 // safe fallback
	}

	// Derive unique seed per record to avoid repeating patterns.
	derivedSeed := sc.seed ^ (n * 0x9E3779B97F4A7C15)
	return RandomizeSize(size, derivedSeed, RecordJitterPercent)
}

// --- net.Conn interface delegation (read path is unshaped) ---

// Read passes through to the inner connection. Only the write path is
// shaped; incoming record sizes are chosen by the peer.
func (sc *ShapedConn) Read(p []byte) (int, error) { return sc.inner.Read(p) }

// Close closes the inner connection. Shaping state is per-connection and
// needs no separate teardown.
func (sc *ShapedConn) Close() error { return sc.inner.Close() }

// LocalAddr returns the inner connection's local address.
func (sc *ShapedConn) LocalAddr() net.Addr { return sc.inner.LocalAddr() }

// RemoteAddr returns the inner connection's remote address.
func (sc *ShapedConn) RemoteAddr() net.Addr { return sc.inner.RemoteAddr() }

// SetDeadline sets the read and write deadlines on the inner connection.
// The deadline covers the whole shaped write, inter-burst pauses included.
func (sc *ShapedConn) SetDeadline(t time.Time) error { return sc.inner.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the inner connection.
func (sc *ShapedConn) SetReadDeadline(t time.Time) error { return sc.inner.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the inner connection. Shaped
// writes pause between bursts, so this deadline must allow for those pauses.
func (sc *ShapedConn) SetWriteDeadline(t time.Time) error { return sc.inner.SetWriteDeadline(t) }

// ConnectionState delegates to the inner connection's TLS state.
// Required by HTTP/2 transport/server which check for this via type assertion.
func (sc *ShapedConn) ConnectionState() tls.ConnectionState {
	type stater interface {
		ConnectionState() tls.ConnectionState
	}
	if cs, ok := sc.inner.(stater); ok {
		return cs.ConnectionState()
	}
	return tls.ConnectionState{}
}

// generateClientSeed creates a cryptographically random per-connection seed.
// Panics if crypto/rand fails — this indicates a broken system RNG,
// which is a fatal condition for a security-critical application.
func generateClientSeed() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("chamele0nx: crypto/rand failed: " + err.Error())
	}
	return binary.LittleEndian.Uint64(buf[:])
}
