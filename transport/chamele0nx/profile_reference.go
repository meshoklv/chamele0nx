package chamele0nx

// RecordJitterPercent is the half-width, as a percentage of the nominal size,
// of the jitter applied to every record the write path emits. It lives here as
// a single constant rather than as a literal at each call site because the
// reference distribution built by [SiteProfile.EmittedSizePMF] has to model
// exactly the jitter the shaper applies. If the two ever drift apart,
// chamele0nx-validator starts measuring the drift instead of the profile, and
// its verdict stops meaning anything — which is precisely how its self-test
// came to report FAIL for every profile ever shipped.
//
// The width follows the FOCI 2024 cross-client correlation defence: two
// connections that pick the same nominal size must not put the same size on
// the wire, or an observer can link them.
const RecordJitterPercent = 25

// EmittedSizePMF returns the distribution of record sizes a peer running this
// profile actually puts on the wire, as a probability mass function indexed by
// payload size in bytes: the value at index n is the probability that a record
// carries exactly n bytes. The slice covers every size a record can legally
// have, so its length also states the domain. Every entry is non-negative and
// the entries sum to one; a size the profile cannot reach holds a value near
// zero rather than exactly zero, so test for one with a tolerance.
//
// This is deliberately not the profile's own histogram. A record is produced in
// three steps — pick a bucket by weight, pick a size uniformly inside it, then
// jitter that size by up to ±[RecordJitterPercent] and clamp the result to a
// legal TLS record payload — and only the first two of those are described by
// RecordSizeDistribution. The histogram is what a profile *asks for*; this is
// what a peer *emits*. Inspection equipment sees the emitted sizes, so those
// are what a statistical test has to be run against.
//
// The gap between the two is not academic. Clamping is what makes it large: a
// bucket whose top reaches the 16 KB record ceiling has a good part of its
// upward jitter folded back onto that one size, leaving an atom several percent
// tall that no histogram of ranges can express. For the shipped saas-fast
// example that atom is around eight percent of all records — the whole of the
// D ≈ 0.083 the validator used to report as a profile defect.
func (p *SiteProfile) EmittedSizePMF() []float64 {
	pmf := make([]float64, maxTLSRecord+1)
	// diff accumulates whole-interval additions, resolved into pmf by one
	// prefix-sum pass at the end. The extra slot lets an interval that ends on
	// the last legal size close without a bounds check.
	diff := make([]float64, maxTLSRecord+2)

	buckets := p.RecordSizeDistribution
	if len(buckets) == 0 {
		// Nothing to describe. An all-zero PMF is the honest answer, and it
		// makes every observed size look impossible — the right verdict for a
		// profile that cannot describe traffic at all.
		return pmf
	}

	// sampleRecordSize walks the buckets accumulating weight and takes the
	// first whose running total covers a uniform draw in [0, 1], falling
	// through to the last bucket if the weights never get there. That walk is
	// modelled here move for move rather than by renormalising the weights,
	// because Validate tolerates them summing to anything within a percent of
	// one, and for such a profile the two models disagree. The reference has
	// to describe the sampler that exists.
	cumulative := 0.0
	for i, b := range buckets {
		covered := min(cumulative, 1)
		cumulative += b.Weight
		share := min(cumulative, 1) - covered
		if i == len(buckets)-1 {
			share = 1 - covered
		}
		if share <= 0 {
			continue
		}

		lo, hi := b.MinSize, b.MaxSize
		if lo > hi {
			// cryptoRandRange returns its lower bound when the range is
			// inverted, so an upside-down bucket is a point mass, not an error.
			hi = lo
		}

		// The draw inside the bucket is uniform, so every nominal size in it
		// carries an equal part of the bucket's share.
		each := share / float64(hi-lo+1)
		for nominal := lo; nominal <= hi; nominal++ {
			spreadJitter(pmf, diff, nominal, each)
		}
	}

	// Resolving the difference array is a long chain of additions and
	// subtractions that cancel exactly in arithmetic but not in binary floating
	// point, so a size that no interval covers can come out holding a residue
	// of a few times 1e-18 — and about half the time a negative one. That is
	// not a cosmetic wart to be tolerated: negative mass is not something a
	// distribution can have, and a caller is entitled to take a logarithm of an
	// entry, or to accumulate these into a CDF and expect it never to go
	// backwards. Each entry is clamped as it is finished.
	//
	// Only negatives are clamped, deliberately. Snapping small positives to
	// zero as well would look tidier and would make the impossible sizes come
	// out as exact zeros, but there is no threshold that is safe for every
	// profile: a bucket sixteen thousand sizes wide carrying a thousandth of
	// the weight has legitimate per-size masses down around 1e-12, which is the
	// same neighbourhood as the residue. Callers that need "is this size
	// possible" should ask with a tolerance rather than against zero.
	running := 0.0
	total := 0.0
	for size := range pmf {
		running += diff[size]
		mass := pmf[size] + running
		if mass < 0 {
			mass = 0
		}
		pmf[size] = mass
		total += mass
	}

	// Clamping discards a sliver of mass and the summation drifts on its own,
	// so renormalise: the documented promise is a distribution, and the
	// validator's CDF is built by accumulating these entries and comparing
	// against an empirical CDF that reaches exactly one.
	if total > 0 {
		for size := range pmf {
			pmf[size] /= total
		}
	}
	return pmf
}

// spreadJitter adds the mass belonging to one nominal record size to the
// emitted distribution, spread across every size [RandomizeSize] can turn that
// nominal into. The two clamp bounds — and sizes too small for the jitter to
// move at all — are point masses and go straight into pmf; the uniform stretch
// between them is a range addition and goes into diff, so a bucket costs time
// proportional to its width rather than to its width times the jitter span.
func spreadJitter(pmf, diff []float64, nominal int, mass float64) {
	if nominal <= 0 || nominal > maxTLSRecord {
		return
	}

	span := nominal * RecordJitterPercent / 100
	if span == 0 {
		// RandomizeSize hands such a size back untouched — and, note, without
		// clamping it either. Mirror that exactly. A reference that quietly
		// disagreed with the shaper on an edge case would show up as a small
		// permanent offset in the D-statistic, indistinguishable from a
		// profile that genuinely does not match.
		pmf[nominal] += mass
		return
	}

	lo, hi := nominal-span, nominal+span
	each := mass / float64(2*span+1)

	// Draws that fall outside the legal payload range are clamped, not
	// discarded, so they pile onto the bounds as atoms instead of vanishing.
	if lo < minTLSRecord {
		below := min(hi, minTLSRecord-1) - lo + 1
		if below > 0 {
			pmf[minTLSRecord] += float64(below) * each
		}
		lo = minTLSRecord
	}
	if hi > maxTLSRecord {
		above := hi - max(lo, maxTLSRecord+1) + 1
		if above > 0 {
			pmf[maxTLSRecord] += float64(above) * each
		}
		hi = maxTLSRecord
	}
	if lo <= hi {
		diff[lo] += each
		diff[hi+1] -= each
	}
}
