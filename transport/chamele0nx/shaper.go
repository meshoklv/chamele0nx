// Package chamele0nx implements the Chamele0nX transport: a protocol that
// hides VPN traffic inside real HTTP/2 sessions by controlling TLS record
// sizes and timing so they match ordinary browsing.
//
// The primary defence is TLS record shaping. Inspection equipment reads
// record-level metadata — sizes, timing, burst structure — because it
// cannot see the HTTP/2 content inside TLS. Shaping makes that metadata
// match a profile measured from a real site rather than betraying a
// tunnel. See docs/en/SPEC.md for the wire format and
// docs/en/THREAT-MODEL.md for what this does and does not achieve.
package chamele0nx

import (
	"crypto/rand"
	"math/big"
)

// TLS record constraints, per RFC 8446.
const (
	// maxTLSRecord is the maximum TLS record payload (2^14).
	maxTLSRecord = 16384
	// minTLSRecord is the smallest record payload worth emitting.
	minTLSRecord = 64
	// tlsRecordHeader is the record header overhead: type, version, length.
	tlsRecordHeader = 5
	// tls13RecordOverhead is the per-record overhead for TLS 1.3 with
	// AES-GCM: one byte of inner content type plus a 16-byte tag.
	// Measured: a Write of N bytes produces N+17 bytes on the wire.
	tls13RecordOverhead = 1 + 16
)

// cryptoRandIntn returns a cryptographically random int in [0, n).
func cryptoRandIntn(n int) (int, error) {
	v, err := cryptoRandInt64n(int64(n))
	return int(v), err
}

// cryptoRandInt64n returns a cryptographically random int64 in [0, n).
//
// Durations are int64 nanoseconds, and converting a range to int before
// drawing overflows on a 32-bit build: any span wider than about 2.1 seconds
// wraps, the draw collapses to zero, and the caller silently returns its
// minimum every single time. For a shaper that is not a rounding error — a
// constant pause is exactly the regularity this project exists to avoid, and
// it would have appeared only on 32-bit targets such as android/arm, never on
// the amd64 machines the tests run on.
func cryptoRandInt64n(n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	val, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0, err
	}
	return val.Int64(), nil
}

// RandomizeSize applies deterministic jitter of up to pct percent to a
// target record size. The same seed always produces the same result, so a
// connection's sizes stay stable while different connections differ.
// The result is clamped to a legal record payload size.
func RandomizeSize(base int, seed uint64, pct int) int {
	if pct <= 0 || base <= 0 {
		return base
	}
	rangeVal := base * pct / 100
	if rangeVal == 0 {
		return base
	}
	jitter := int(seed%(uint64(2*rangeVal+1))) - rangeVal
	result := base + jitter
	if result < minTLSRecord {
		result = minTLSRecord
	}
	if result > maxTLSRecord {
		result = maxTLSRecord
	}
	return result
}
