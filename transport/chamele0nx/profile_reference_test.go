package chamele0nx

import (
	"math"
	"testing"
)

// referenceProfiles are the profiles the reference distribution is checked
// against: every built-in shape, so a new preset with an unusual histogram
// cannot quietly break the model the validator depends on.
func referenceProfiles() map[string]*SiteProfile {
	return map[string]*SiteProfile{
		"balanced":          DefaultBalancedProfile(),
		"stealth":           DefaultStealthProfile(),
		"aggressive":        DefaultAggressiveProfile(),
		"wordpress":         DefaultWordPressProfile(),
		"lowpower":          DefaultLowPowerProfile(),
		"server-downstream": DefaultServerDownstreamProfile(),
		"client-upstream":   DefaultClientUpstreamProfile(),
	}
}

func TestEmittedSizePMFIsAProbabilityDistribution(t *testing.T) {
	for name, p := range referenceProfiles() {
		pmf := p.EmittedSizePMF()

		total := 0.0
		for size, m := range pmf {
			if m < 0 {
				t.Fatalf("%s: negative probability %g at size %d", name, m, size)
			}
			total += m
		}
		if math.Abs(total-1) > 1e-9 {
			t.Errorf("%s: probabilities sum to %.12f, want 1", name, total)
		}
	}
}

// TestEmittedSizePMFModelsTheClampAtom pins the specific thing whose absence
// broke the validator for two years' worth of profiles: jitter pushed past the
// record ceiling is clamped back onto it, so the largest legal size carries an
// atom. A reference built from the bucket histogram alone has no atom there,
// and the resulting offset is exactly the D the tool used to report.
func TestEmittedSizePMFModelsTheClampAtom(t *testing.T) {
	atTheCeiling := &SiteProfile{
		Version:                1,
		RecordSizeDistribution: []SizeBucket{{MinSize: 10000, MaxSize: maxTLSRecord, Weight: 1.0}},
	}
	pmf := atTheCeiling.EmittedSizePMF()
	if got := pmf[maxTLSRecord]; got < 0.05 {
		t.Errorf("atom at the record ceiling = %g, want a substantial one (>0.05): "+
			"clamped jitter is not being modelled", got)
	}

	// This profile's jitter reaches 2500 at the very most, so nothing can land
	// on the record ceiling and the entry there should be zero. It is compared
	// with a tolerance rather than against zero: resolving the model leaves a
	// residue of a few times 1e-18 on sizes no interval covers, and the bound
	// is orders of magnitude below the smallest mass any real profile puts on a
	// single size. The value is printed with %g so a failure shows whether it
	// is that residue or a genuine atom — the two are indistinguishable at four
	// decimal places, which is how this assertion first failed with a message
	// that read "= 0.0000 ... want 0" and explained nothing.
	const negligible = 1e-12

	wellBelowTheCeiling := &SiteProfile{
		Version:                1,
		RecordSizeDistribution: []SizeBucket{{MinSize: 1000, MaxSize: 2000, Weight: 1.0}},
	}
	pmf = wellBelowTheCeiling.EmittedSizePMF()
	if got := pmf[maxTLSRecord]; got > negligible {
		t.Errorf("atom at the record ceiling = %g for a profile whose jitter cannot reach it, want at most %g",
			got, negligible)
	}
}

// TestEmittedSizePMFCoversTheJitterSkirts asserts that the reference places
// mass outside the buckets themselves. Jitter routinely carries a record past
// the edge of the bucket it was drawn from, and a test that counted only
// within the buckets — as the χ² test once did — throws those records away.
func TestEmittedSizePMFCoversTheJitterSkirts(t *testing.T) {
	p := &SiteProfile{
		Version:                1,
		RecordSizeDistribution: []SizeBucket{{MinSize: 4000, MaxSize: 8000, Weight: 1.0}},
	}
	pmf := p.EmittedSizePMF()

	below, above := 0.0, 0.0
	for size := minTLSRecord; size < 4000; size++ {
		below += pmf[size]
	}
	for size := 8001; size <= maxTLSRecord; size++ {
		above += pmf[size]
	}
	if below <= 0 {
		t.Error("no mass below the only bucket: downward jitter is not modelled")
	}
	if above <= 0 {
		t.Error("no mass above the only bucket: upward jitter is not modelled")
	}
}

// TestEmittedSizePMFMatchesGenerateBurst is the test that keeps the reference
// honest: it compares the model against what the sampler actually produces. If
// either side changes — a different jitter width, a different draw inside a
// bucket, a clamp that moves — the two CDFs part company and this fails.
//
// The tolerance is set from the sampling noise rather than by taste. With n
// draws the empirical CDF sits within about 0.5/sqrt(n) of the true one at any
// single point, so at n = 40 000 one standard error is 0.0025 and a bound of
// 0.015 is six of them: a false failure is far rarer than a flaky machine.
// The defect this replaces sat at 0.083 for the shipped saas-fast shape, five
// times the bound.
func TestEmittedSizePMFMatchesGenerateBurst(t *testing.T) {
	const wanted = 40000
	const tolerance = 0.015

	for name, p := range referenceProfiles() {
		pmf := p.EmittedSizePMF()

		counts := make([]float64, len(pmf))
		drawn := 0
		for drawn < wanted {
			// A fresh full-entropy seed per burst, exactly as a real client
			// draws for itself. Sequential seeds would leave the jitter's low
			// bits barely moving, and this would measure that instead of the
			// model.
			burst, err := p.GenerateBurst(generateClientSeed())
			if err != nil {
				t.Fatalf("%s: generate burst: %v", name, err)
			}
			for _, size := range burst.RecordSizes {
				if size < 0 || size >= len(counts) {
					t.Fatalf("%s: generated size %d outside the legal record range", name, size)
				}
				counts[size]++
				drawn++
			}
		}

		empirical, model, worst := 0.0, 0.0, 0.0
		for size := range pmf {
			empirical += counts[size] / float64(drawn)
			model += pmf[size]
			if d := math.Abs(empirical - model); d > worst {
				worst = d
			}
		}
		if worst > tolerance {
			t.Errorf("%s: model and sampler differ by %.4f at worst (tolerance %.4f) over %d draws",
				name, worst, tolerance, drawn)
		}
	}
}
