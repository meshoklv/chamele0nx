package main

import (
	"math"
	mathrand "math/rand/v2"
	"path/filepath"
	"testing"

	"github.com/meshoklv/chamele0nx/transport/chamele0nx"
)

// The shipped example profiles are the ones CONTRIBUTING points contributors
// at, so they are the ones the gate has to work on. Loading them from disk
// rather than restating their shape here also means a careless edit to an
// example is caught by this package rather than in the field.
const (
	fastProfile    = "saas-fast.example.json"
	stealthProfile = "saas-stealth.example.json"
)

func loadExample(t *testing.T, name string) *chamele0nx.SiteProfile {
	t.Helper()
	p, err := chamele0nx.LoadProfile(filepath.Join("..", "..", "deploy", "profiles", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return p
}

// emittedSamples collects at least n record sizes the way a fleet of clients
// running this profile would produce them: whole bursts, each with its own
// full-entropy seed.
func emittedSamples(t *testing.T, p *chamele0nx.SiteProfile, n int) []int {
	t.Helper()
	samples := make([]int, 0, n)
	for len(samples) < n {
		seed, err := randomSeed()
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		burst, err := p.GenerateBurst(seed)
		if err != nil {
			t.Fatalf("generate burst: %v", err)
		}
		samples = append(samples, burst.RecordSizes...)
	}
	return samples
}

// nominalSamples draws sizes straight from the profile's bucket histogram with
// no jitter at all: the distribution the profile describes, rather than the one
// a peer emits. Deterministic, so a failure here is reproducible.
func nominalSamples(p *chamele0nx.SiteProfile, n int) []int {
	r := mathrand.New(mathrand.NewPCG(0x0C1EA12E, 0x5EEDF00D))
	buckets := p.RecordSizeDistribution

	samples := make([]int, 0, n)
	for len(samples) < n {
		u := r.Float64()
		chosen := buckets[len(buckets)-1]
		cumulative := 0.0
		for _, b := range buckets {
			cumulative += b.Weight
			if u <= cumulative {
				chosen = b
				break
			}
		}
		samples = append(samples, chosen.MinSize+r.IntN(chosen.MaxSize-chosen.MinSize+1))
	}
	return samples
}

// TestGateAcceptsTrafficTheProfileEmits is the regression test for the defect
// this tool carried from the day it was written: it tested the sizes a peer
// emits against the histogram those sizes are drawn from *before* jitter, so
// the verdict was FAIL for every profile, at every sample size, for ever.
//
// It is run at α = 1e-6 rather than the usual 0.05 on purpose. At the ordinary
// level a correct model still fails one run in twenty by construction — the
// p-value of a true null hypothesis is uniform — and a gate that flakes five
// percent of the time gets ignored, which is how the previous defect survived.
// A false failure here needs a one-in-a-million draw instead.
//
// The D-statistic is bounded separately so that a failure says which way the
// model is wrong. Three over the square root of the sample count is about 3.4
// standard errors; the defect being fixed sat at 0.083 for saas-fast and 0.015
// for saas-stealth, which at this sample size are 32 and 5.8.
func TestGateAcceptsTrafficTheProfileEmits(t *testing.T) {
	const samples = 150000
	const maxLambda = 3.0

	for _, name := range []string{fastProfile, stealthProfile} {
		p := loadExample(t, name)
		drawn := emittedSamples(t, p, samples)
		rep := evaluate(drawn, p, 1e-6)

		if lambda := rep.KSStat * math.Sqrt(float64(len(drawn))); lambda > maxLambda {
			t.Errorf("%s: KS D = %.5f (%.1f standard errors, limit %.1f)",
				name, rep.KSStat, lambda, maxLambda)
		}
		// A χ² run down to one or two bands cannot disagree with anything, so
		// a PASS from it would be a PASS from having nothing to compare. The
		// example profiles both have four buckets and should leave well more
		// bands than this even after thin ones are merged.
		if rep.ChiDF < 5 {
			t.Errorf("%s: χ² ran on %d degrees of freedom — too few bands to mean anything",
				name, rep.ChiDF)
		}
		if !rep.pass() {
			t.Errorf("%s: gate rejects the profile's own traffic — KS D=%.5f p=%.3g, χ²=%.1f df=%d p=%.3g",
				name, rep.KSStat, rep.KSPValue, rep.ChiStat, rep.ChiDF, rep.ChiPValue)
		}
	}
}

// TestGateRejectsUnjitteredTraffic is the mirror image of the test above, and
// the reason both are needed. Sizes drawn from the bucket histogram alone are
// not what the shaper emits, so the gate must refuse them. Anyone who "fixes"
// a future failure by dropping the jitter back out of the reference makes this
// test fail, which is the point: the accepting test alone could be satisfied
// by a reference that accepts everything.
func TestGateRejectsUnjitteredTraffic(t *testing.T) {
	const samples = 100000

	p := loadExample(t, fastProfile)
	rep := evaluate(nominalSamples(p, samples), p, 0.05)

	if rep.KSPass {
		t.Errorf("KS accepted un-jittered sizes: D = %.5f, p = %.4f", rep.KSStat, rep.KSPValue)
	}
	if rep.ChiPass {
		t.Errorf("χ² accepted un-jittered sizes: χ² = %.1f, df = %d, p = %.4f",
			rep.ChiStat, rep.ChiDF, rep.ChiPValue)
	}
}

// TestGateRejectsAnotherProfilesTraffic checks the plainest kind of mismatch:
// real shaped traffic, but from a profile with a different shape.
func TestGateRejectsAnotherProfilesTraffic(t *testing.T) {
	const samples = 20000

	fast := loadExample(t, fastProfile)
	stealth := loadExample(t, stealthProfile)

	rep := evaluate(emittedSamples(t, stealth, samples), fast, 0.05)
	if rep.pass() {
		t.Errorf("gate accepted %s traffic as %s: KS D = %.5f p = %.4f",
			stealth.Name, fast.Name, rep.KSStat, rep.KSPValue)
	}
}

// TestGateRejectsShiftedTraffic checks a mismatch too small to see in a
// histogram drawn by eye: the right shape, every size fifteen percent larger.
// A reference wide enough to swallow this would be wide enough to swallow
// anything.
func TestGateRejectsShiftedTraffic(t *testing.T) {
	const samples = 20000

	p := loadExample(t, fastProfile)
	shifted := emittedSamples(t, p, samples)
	for i, s := range shifted {
		grown := int(float64(s) * 1.15)
		if grown > 16384 {
			grown = 16384
		}
		shifted[i] = grown
	}

	rep := evaluate(shifted, p, 0.05)
	if rep.pass() {
		t.Errorf("gate accepted uniformly enlarged sizes: KS D = %.5f p = %.4f, χ² p = %.4f",
			rep.KSStat, rep.KSPValue, rep.ChiPValue)
	}
}

// TestGateRefusesTooFewSamples guards the other way a gate goes quiet: passing
// because it was handed too little to judge.
func TestGateRefusesTooFewSamples(t *testing.T) {
	if err := checkSampleCount(minSamples - 1); err == nil {
		t.Errorf("%d samples accepted, want a refusal", minSamples-1)
	}
	if err := checkSampleCount(minSamples); err != nil {
		t.Errorf("%d samples refused: %v", minSamples, err)
	}
}

// TestBandCutsTileTheDomain pins the property the χ² test relies on: the bands
// cover every possible record size exactly once. A gap would silently discard
// observations, which is how the old implementation lost every record jitter
// had carried out of its bucket.
func TestBandCutsTileTheDomain(t *testing.T) {
	for _, name := range []string{fastProfile, stealthProfile} {
		p := loadExample(t, name)
		ref := newReference(p)

		if len(ref.cuts) < 2 {
			t.Fatalf("%s: %d band boundaries, want at least 2", name, len(ref.cuts))
		}
		if ref.cuts[0] != 0 {
			t.Errorf("%s: bands start at %d, want 0", name, ref.cuts[0])
		}
		if last := ref.cuts[len(ref.cuts)-1]; last != len(ref.pmf) {
			t.Errorf("%s: bands end at %d, want %d", name, last, len(ref.pmf))
		}
		for i := 1; i < len(ref.cuts); i++ {
			if ref.cuts[i] <= ref.cuts[i-1] {
				t.Fatalf("%s: band boundaries %d and %d are out of order",
					name, ref.cuts[i-1], ref.cuts[i])
			}
		}
	}
}
