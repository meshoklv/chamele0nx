package chamele0nx

import (
	"math"
	"testing"
	"time"
)

// TestCryptoRandDurationWideRange guards against the 32-bit overflow that
// collapsed timing entropy to a constant.
//
// cryptoRandDuration used to convert its span to int before drawing. A
// time.Duration is int64 nanoseconds, so on a 32-bit build any span wider
// than about 2.1 seconds wrapped, the draw returned zero, and the function
// handed back its minimum every time. A shaper whose pauses are a fixed
// number is precisely the regularity this project exists to remove — and it
// would have shown up only on targets like android/arm, never on the amd64
// machines the tests run on.
//
// The test asserts the property directly rather than the arithmetic: over a
// span far wider than a 32-bit nanosecond count, the results must vary and
// must cover the range rather than piling onto the minimum.
func TestCryptoRandDurationWideRange(t *testing.T) {
	const (
		min = 1 * time.Second
		max = 60 * time.Second // 6e10 ns, far past the 2^31 wrap point
	)

	seen := make(map[time.Duration]struct{})
	atMin := 0
	const draws = 200

	for i := 0; i < draws; i++ {
		d, err := cryptoRandDuration(min, max)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if d < min || d > max {
			t.Fatalf("draw %d returned %s, outside [%s, %s]", i, d, min, max)
		}
		seen[d] = struct{}{}
		if d == min {
			atMin++
		}
	}

	if len(seen) < draws/2 {
		t.Errorf("only %d distinct values in %d draws — the range collapsed", len(seen), draws)
	}
	if atMin > draws/10 {
		t.Errorf("%d of %d draws returned exactly the minimum — the span overflowed", atMin, draws)
	}
}

// TestCryptoRandInt64nWidth covers the helper directly at a width that does
// not fit in a 32-bit int.
func TestCryptoRandInt64nWidth(t *testing.T) {
	const n = int64(math.MaxInt32) * 16

	seen := make(map[int64]struct{})
	for i := 0; i < 100; i++ {
		v, err := cryptoRandInt64n(n)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if v < 0 || v >= n {
			t.Fatalf("draw %d returned %d, outside [0, %d)", i, v, n)
		}
		seen[v] = struct{}{}
	}
	if len(seen) < 90 {
		t.Errorf("only %d distinct values in 100 draws from a %d-wide range", len(seen), n)
	}

	// Degenerate widths must be handled, not panic.
	for _, bad := range []int64{0, -1, math.MinInt64} {
		if v, err := cryptoRandInt64n(bad); err != nil || v != 0 {
			t.Errorf("cryptoRandInt64n(%d) = (%d, %v), want (0, nil)", bad, v, err)
		}
	}
}

// TestCryptoRandDurationDegenerate pins the documented edge cases.
func TestCryptoRandDurationDegenerate(t *testing.T) {
	for _, tc := range []struct{ min, max time.Duration }{
		{5 * time.Second, 5 * time.Second}, // equal
		{9 * time.Second, 2 * time.Second}, // inverted
	} {
		d, err := cryptoRandDuration(tc.min, tc.max)
		if err != nil {
			t.Fatalf("(%s, %s): %v", tc.min, tc.max, err)
		}
		if d != tc.min {
			t.Errorf("(%s, %s) returned %s, want %s", tc.min, tc.max, d, tc.min)
		}
	}
}
