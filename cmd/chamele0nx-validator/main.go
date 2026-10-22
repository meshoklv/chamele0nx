// chamele0nx-validator compares observed traffic against a SiteProfile using
// statistical tests. It answers: "Does our shaped traffic pass as the real site?"
//
// Usage:
//
//	chamele0nx-validator -profile profile.json -samples samples.json
//	chamele0nx-validator -profile profile.json -generate 1000
//
// Modes:
//   - Compare mode: reads captured samples and tests against profile.
//   - Generate mode: generates synthetic samples from the profile and self-tests.
//
// Both modes test against the same reference: the distribution of record sizes
// a peer running this profile actually emits, per-record jitter and record-size
// clamping included. See [chamele0nx.SiteProfile.EmittedSizePMF]. Testing
// against the raw bucket histogram instead measures the shaper's jitter rather
// than the profile, and reports a mismatch that no edit to the profile could
// ever fix; that is what this tool did until the reference was corrected.
//
// Statistical tests:
//   - Kolmogorov-Smirnov (KS) test: are record sizes from the same distribution?
//   - Chi-squared (χ²) test: do the per-size-band counts match the reference?
//
// Exit code 0 = pass, 1 = fail.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"

	"github.com/meshoklv/chamele0nx/transport/chamele0nx"
)

// minSamples is the fewest samples this tool will render a verdict on. Below
// it neither test has the power to tell a matching profile from a mismatched
// one, so a PASS would mean only that too little was looked at — the failure
// mode of a gate that is worse than no gate, because it reads as evidence.
const minSamples = 200

// minExpectedPerBin is the smallest expected count a χ² bin may carry. The
// approximation behind the statistic degrades on thin bins, and a bin
// expecting a fraction of a sample contributes noise rather than evidence, so
// bins below this are merged into their neighbours.
const minExpectedPerBin = 5.0

// defaultAlpha is the significance level for comparing captured traffic against
// a profile: the conventional 0.05, where a false alarm one time in twenty is
// an acceptable price for noticing a profile that has drifted.
//
// selfTestAlpha is the level -generate uses instead, and the comment where it
// is applied explains why the two differ.
const (
	defaultAlpha  = 0.05
	selfTestAlpha = 1e-4
)

func main() {
	profilePath := flag.String("profile", "", "Path to SiteProfile JSON")
	samplesPath := flag.String("samples", "", "Path to samples JSON (array of record sizes)")
	generateN := flag.Int("generate", 0, "Generate N synthetic bursts and self-test")
	alpha := flag.Float64("alpha", defaultAlpha, "Significance level for statistical tests")
	flag.Parse()
	alphaWasSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "alpha" {
			alphaWasSet = true
		}
	})
	exitIfVersionRequested("chamele0nx-validator")

	if *profilePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	profile, err := chamele0nx.LoadProfile(*profilePath)
	if err != nil {
		log.Fatalf("load profile: %v", err)
	}

	var samples []int

	switch {
	case *generateN > 0:
		// The self-test compares a profile against traffic drawn from that same
		// profile, so the hypothesis being tested is true by construction. At
		// the customary 0.05 a correct implementation is therefore expected to
		// report FAIL about one run in twenty — measured here at twenty runs of
		// saas-stealth, whose p-values came out spread evenly across the range
		// with exactly one below 0.05. A gate that cries wolf on schedule gets
		// switched off by the people it is meant to protect, so the self-test
		// asks a stricter question by default: not "is this traffic plausibly
		// from this profile" but "is the model broken". An explicit -alpha
		// still wins, which is what makes the flakiness reproducible on demand.
		if !alphaWasSet {
			*alpha = selfTestAlpha
		}

		// Generate synthetic samples from the profile.
		log.Printf("Generating %d synthetic bursts from profile %q...", *generateN, profile.Name)
		for i := 0; i < *generateN; i++ {
			// A fresh random seed per burst, because that is what a fleet of
			// clients looks like: each one draws its own. Walking 0, 1, 2, …
			// would hand the jitter seeds whose low bits barely move, and the
			// modulo inside RandomizeSize would turn that into a bias in the
			// very statistic being measured.
			seed, err := randomSeed()
			if err != nil {
				log.Fatalf("seed: %v", err)
			}
			burst, err := profile.GenerateBurst(seed)
			if err != nil {
				log.Fatalf("generate burst: %v", err)
			}
			samples = append(samples, burst.RecordSizes...)
		}
	case *samplesPath != "":
		data, err := os.ReadFile(*samplesPath)
		if err != nil {
			log.Fatalf("read samples: %v", err)
		}
		if err := json.Unmarshal(data, &samples); err != nil {
			log.Fatalf("parse samples: %v", err)
		}
	default:
		log.Fatal("provide -samples or -generate")
	}

	if err := checkSampleCount(len(samples)); err != nil {
		log.Fatalf("%v", err)
	}

	log.Printf("Testing %d samples against profile %q (α=%g)...", len(samples), profile.Name, *alpha)

	rep := evaluate(samples, profile, *alpha)

	// Print results.
	fmt.Println()
	fmt.Printf("Reference: sizes this profile emits — bucket histogram, ±%d%% per-record\n", chamele0nx.RecordJitterPercent)
	fmt.Printf("           jitter, and clamping to a legal TLS record payload.\n")
	fmt.Println()
	fmt.Printf("=== Kolmogorov-Smirnov Test ===\n")
	fmt.Printf("  D-statistic: %.4f\n", rep.KSStat)
	fmt.Printf("  p-value:     %.4f\n", rep.KSPValue)
	fmt.Printf("  Result:      %s\n", passFail(rep.KSPass))
	fmt.Println()
	fmt.Printf("=== Chi-Squared Test ===\n")
	fmt.Printf("  χ²-statistic: %.4f\n", rep.ChiStat)
	fmt.Printf("  deg. freedom: %d\n", rep.ChiDF)
	fmt.Printf("  p-value:      %.4f\n", rep.ChiPValue)
	fmt.Printf("  Result:       %s\n", passFail(rep.ChiPass))
	fmt.Println()

	if rep.pass() {
		fmt.Println("OVERALL: PASS — traffic matches profile")
		os.Exit(0)
	} else {
		fmt.Println("OVERALL: FAIL — traffic does NOT match profile")
		os.Exit(1)
	}
}

func passFail(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

// checkSampleCount refuses to judge a sample too small to judge. It is a
// separate function so the refusal is testable: a gate that quietly passes
// three samples is the failure this whole tool exists to avoid.
func checkSampleCount(n int) error {
	if n < minSamples {
		return fmt.Errorf("only %d samples: below %d neither test can tell a matching "+
			"profile from a mismatched one, so a verdict here would be noise", n, minSamples)
	}
	return nil
}

// randomSeed draws a 64-bit client seed, the same shape of value a real client
// generates for itself when it opens a connection.
func randomSeed() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// report is the outcome of one validation run: both statistics, both p-values,
// and the verdict each one carries at the chosen significance level.
type report struct {
	KSStat, KSPValue   float64
	ChiStat, ChiPValue float64
	ChiDF              int
	KSPass, ChiPass    bool
}

// pass is the overall verdict. Both tests have to agree, because they see
// different things: KS is sensitive to a distribution shifted as a whole, χ²
// to mass that has moved between size bands without moving the shape much.
func (r report) pass() bool { return r.KSPass && r.ChiPass }

// evaluate runs both goodness-of-fit tests against the sizes the profile
// emits, and applies the significance level to each.
func evaluate(samples []int, profile *chamele0nx.SiteProfile, alpha float64) report {
	ref := newReference(profile)
	counts, n := tally(samples, len(ref.cdf))

	ksStat, ksPValue := ksTest(counts, n, ref)
	chiStat, chiPValue, df := chiSquaredTest(counts, n, ref)

	return report{
		KSStat:    ksStat,
		KSPValue:  ksPValue,
		ChiStat:   chiStat,
		ChiPValue: chiPValue,
		ChiDF:     df,
		KSPass:    ksPValue > alpha,
		ChiPass:   chiPValue > alpha,
	}
}

// reference is the distribution samples are tested against: the sizes a peer
// running the profile emits, held as a probability mass function, its running
// total, and the boundaries of the bands the χ² test counts within.
type reference struct {
	pmf []float64
	cdf []float64
	// cuts are ascending band boundaries. Band i covers sizes
	// [cuts[i], cuts[i+1]), and the last cut is one past the largest size,
	// so the bands tile the whole domain with nothing left over.
	cuts []int
}

func newReference(profile *chamele0nx.SiteProfile) *reference {
	pmf := profile.EmittedSizePMF()
	cdf := make([]float64, len(pmf))
	running := 0.0
	for i, m := range pmf {
		running += m
		cdf[i] = running
	}
	return &reference{pmf: pmf, cdf: cdf, cuts: bandCuts(profile, len(pmf))}
}

// bandCuts chooses the boundaries the χ² test counts between.
//
// The profile's own bucket edges are the obvious choice and they are all the
// old implementation used — which is why it dropped every sample that jitter
// had carried into the gap between two buckets, or past the last one. Those
// samples are not anomalies to be discarded; they are the ordinary output of
// the shaper, and a test that cannot see them cannot see the skirts where a
// mismatch shows up first. So each bucket also contributes the two sizes its
// jitter can reach, and every gap between buckets becomes a band of its own.
func bandCuts(profile *chamele0nx.SiteProfile, domain int) []int {
	seen := map[int]bool{0: true, domain: true}
	add := func(v int) {
		if v > 0 && v < domain {
			seen[v] = true
		}
	}
	for _, b := range profile.RecordSizeDistribution {
		if b.MinSize > b.MaxSize {
			continue
		}
		add(b.MinSize)
		add(b.MaxSize + 1)
		// The reach of the jitter on each end: the smallest size the bucket's
		// floor can be pushed down to, and one past the largest its ceiling
		// can be pushed up to.
		add(b.MinSize - b.MinSize*chamele0nx.RecordJitterPercent/100)
		add(b.MaxSize + b.MaxSize*chamele0nx.RecordJitterPercent/100 + 1)
	}

	cuts := make([]int, 0, len(seen))
	for c := range seen {
		cuts = append(cuts, c)
	}
	sort.Ints(cuts)
	return cuts
}

// tally counts samples into one slot per possible record size, and returns the
// slots alongside the total number of samples seen.
//
// Samples outside the legal range are handled rather than skipped. A negative
// size is counted at the bottom of the domain; a size above the ceiling is
// counted in the total but in no slot, which leaves the empirical CDF short of
// one by exactly the missing mass. Either way the anomaly reaches the
// statistic instead of disappearing, because a validator that silently drops
// the samples it cannot explain is a validator that passes everything.
func tally(samples []int, domain int) (counts []float64, n float64) {
	counts = make([]float64, domain)
	for _, s := range samples {
		switch {
		case s < 0:
			counts[0]++
		case s >= domain:
			// Deliberately uncounted; see above.
		default:
			counts[s]++
		}
	}
	return counts, float64(len(samples))
}

// ksTest performs a one-sample Kolmogorov-Smirnov test comparing the empirical
// CDF of the samples against the reference CDF.
//
// Record sizes are whole bytes, so both CDFs are step functions that move only
// at integers and are flat between them. The supremum of their difference is
// therefore attained at one of those integers, and walking the domain once is
// exact — no sort, and no need to probe either side of a step.
//
// The p-value uses the asymptotic Kolmogorov distribution, which assumes a
// continuous reference. Against a discrete one it is conservative: the true
// distribution of D is stochastically smaller, so the test rejects less often
// than α suggests. That is the safe direction for a gate — it does not cry
// wolf — but it does mean a PASS is weaker evidence than a FAIL.
func ksTest(counts []float64, n float64, ref *reference) (dStat, pValue float64) {
	if n == 0 {
		return 0, 1
	}

	seen := 0.0
	for size, c := range counts {
		seen += c
		if d := math.Abs(seen/n - ref.cdf[size]); d > dStat {
			dStat = d
		}
	}

	// Approximate p-value using the Kolmogorov distribution.
	// For large n: P(D > d) ≈ 2 * Σ (-1)^(k-1) * exp(-2k²n d²)
	sqrtN := math.Sqrt(n)
	lambda := (sqrtN + 0.12 + 0.11/sqrtN) * dStat
	pValue = 0
	for k := 1; k <= 100; k++ {
		sign := 1.0
		if k%2 == 0 {
			sign = -1.0
		}
		term := sign * math.Exp(-2.0*float64(k)*float64(k)*lambda*lambda)
		pValue += term
	}
	pValue *= 2
	if pValue < 0 {
		pValue = 0
	}
	if pValue > 1 {
		pValue = 1
	}

	return dStat, pValue
}

// chiSquaredTest performs a chi-squared goodness-of-fit test of the observed
// counts per size band against the counts the reference distribution predicts.
//
// Bands too thin to expect minExpectedPerBin samples are merged into their
// neighbours rather than skipped. Skipping was the old behaviour and it is
// unsound twice over: the discarded observations leave the remaining bands
// summing to less than the sample count, and the degrees of freedom no longer
// match the bands actually compared.
func chiSquaredTest(counts []float64, n float64, ref *reference) (chiStat, pValue float64, df int) {
	if n == 0 || len(ref.cuts) < 2 {
		return 0, 1, 0
	}

	// Every sample above the ceiling is folded into the top band. It cannot be
	// dropped — a profile that emits sizes it has no way to produce is exactly
	// what this test should catch — and the reference expects none of them, so
	// each one pushes the statistic towards rejection.
	observedTotal := 0.0
	for _, c := range counts {
		observedTotal += c
	}
	aboveCeiling := n - observedTotal

	var observed, expected []float64
	accObs, accExp := 0.0, 0.0
	for i := 0; i+1 < len(ref.cuts); i++ {
		lo, hi := ref.cuts[i], ref.cuts[i+1]
		for size := lo; size < hi; size++ {
			accObs += counts[size]
			accExp += ref.pmf[size] * n
		}
		if i+2 == len(ref.cuts) {
			accObs += aboveCeiling
		}
		if accExp >= minExpectedPerBin {
			observed = append(observed, accObs)
			expected = append(expected, accExp)
			accObs, accExp = 0, 0
		}
	}
	// Whatever is left over is too thin to stand alone; fold it into the last
	// band so no observation is lost.
	if accObs != 0 || accExp != 0 {
		if len(observed) > 0 {
			observed[len(observed)-1] += accObs
			expected[len(expected)-1] += accExp
		} else {
			observed = append(observed, accObs)
			expected = append(expected, accExp)
		}
	}

	// χ² = Σ (observed - expected)² / expected
	for i := range observed {
		if expected[i] <= 0 {
			continue
		}
		diff := observed[i] - expected[i]
		chiStat += diff * diff / expected[i]
	}

	// One band cannot disagree with itself: with a single band the statistic
	// is identically zero and a PASS would say nothing at all. Report zero
	// degrees of freedom and a p-value of zero so the run fails loudly rather
	// than passing vacuously.
	df = len(observed) - 1
	if df < 1 {
		return chiStat, 0, 0
	}

	// Approximate p-value using Wilson-Hilferty transformation.
	// For χ² with df degrees: Z ≈ ((χ²/df)^(1/3) - (1 - 2/(9*df))) / sqrt(2/(9*df))
	ratio := chiStat / float64(df)
	term := 2.0 / (9.0 * float64(df))
	z := (math.Pow(ratio, 1.0/3.0) - (1 - term)) / math.Sqrt(term)

	// Standard normal CDF for the upper tail.
	pValue = 0.5 * math.Erfc(z/math.Sqrt2)

	return chiStat, pValue, df
}
