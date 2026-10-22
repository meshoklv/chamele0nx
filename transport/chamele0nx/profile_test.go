package chamele0nx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultSaaSProfileValid(t *testing.T) {
	p := DefaultSaaSProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("default profile invalid: %v", err)
	}
}

func TestProfileJSON(t *testing.T) {
	p := DefaultSaaSProfile()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("profile JSON:\n%s", data)

	var p2 SiteProfile
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p2.Validate(); err != nil {
		t.Fatalf("roundtrip profile invalid: %v", err)
	}
	if p2.Name != p.Name {
		t.Errorf("name mismatch: %q vs %q", p2.Name, p.Name)
	}
	if len(p2.RecordSizeDistribution) != len(p.RecordSizeDistribution) {
		t.Errorf("distribution len mismatch")
	}
}

func TestLoadProfile(t *testing.T) {
	p := DefaultSaaSProfile()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Name != p.Name {
		t.Errorf("name mismatch: %q vs %q", loaded.Name, p.Name)
	}
}

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*SiteProfile)
		errMsg string
	}{
		{
			name:   "bad version",
			modify: func(p *SiteProfile) { p.Version = 0 },
			errMsg: "unsupported version",
		},
		{
			name:   "empty distribution",
			modify: func(p *SiteProfile) { p.RecordSizeDistribution = nil },
			errMsg: "empty record size distribution",
		},
		{
			name: "bad bucket range",
			modify: func(p *SiteProfile) {
				p.RecordSizeDistribution[0].MinSize = 5000
				p.RecordSizeDistribution[0].MaxSize = 100
			},
			errMsg: "min",
		},
		{
			name:   "bad upload ratio",
			modify: func(p *SiteProfile) { p.UploadDownloadRatio = 2.0 },
			errMsg: "upload/download ratio",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := DefaultSaaSProfile()
			tt.modify(p)
			err := p.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			t.Logf("got expected error: %v", err)
		})
	}
}

func TestGenerateBurst(t *testing.T) {
	p := DefaultSaaSProfile()
	seed := uint64(0xDEADBEEF)

	for i := 0; i < 10; i++ {
		burst, err := p.GenerateBurst(seed + uint64(i))
		if err != nil {
			t.Fatalf("generate burst: %v", err)
		}

		if len(burst.RecordSizes) < p.BurstPattern.RecordsPerBurst.Min ||
			len(burst.RecordSizes) > p.BurstPattern.RecordsPerBurst.Max {
			t.Errorf("burst %d: %d records outside [%d, %d]",
				i, len(burst.RecordSizes),
				p.BurstPattern.RecordsPerBurst.Min,
				p.BurstPattern.RecordsPerBurst.Max)
		}

		for j, size := range burst.RecordSizes {
			if size < minTLSRecord || size > maxTLSRecord {
				t.Errorf("burst %d record %d: size %d outside TLS bounds", i, j, size)
			}
		}
	}
}

// TestPersonalizeForDeterministic verifies that the same seed always
// produces the same personalized profile (same weights, same ranges).
// This is the load-bearing property — without determinism, every
// reconnect would reshape and DPI would see a profile flip mid-session.
func TestPersonalizeForDeterministic(t *testing.T) {
	base := DefaultSaaSProfile()
	const seed = uint64(0xDEADBEEFCAFEBABE)

	a := base.PersonalizeFor(seed)
	b := base.PersonalizeFor(seed)

	if a == b {
		t.Fatal("PersonalizeFor returned the same pointer twice — must be a deep copy")
	}
	if len(a.RecordSizeDistribution) != len(b.RecordSizeDistribution) {
		t.Fatalf("len mismatch: %d vs %d", len(a.RecordSizeDistribution), len(b.RecordSizeDistribution))
	}
	for i := range a.RecordSizeDistribution {
		if a.RecordSizeDistribution[i].Weight != b.RecordSizeDistribution[i].Weight {
			t.Errorf("bucket %d weight non-deterministic: %f vs %f",
				i, a.RecordSizeDistribution[i].Weight, b.RecordSizeDistribution[i].Weight)
		}
	}
	if a.BurstPattern.RecordsPerBurst != b.BurstPattern.RecordsPerBurst {
		t.Errorf("RecordsPerBurst non-deterministic: %+v vs %+v",
			a.BurstPattern.RecordsPerBurst, b.BurstPattern.RecordsPerBurst)
	}
	if a.BurstPattern.InterBurstPause != b.BurstPattern.InterBurstPause {
		t.Errorf("InterBurstPause non-deterministic: %+v vs %+v",
			a.BurstPattern.InterBurstPause, b.BurstPattern.InterBurstPause)
	}
}

// TestPersonalizeForDifferentSeedsDiverge verifies that different seeds
// produce different parameters across the personalized fields. This is
// the point of personalization: cross-client correlation drops because the
// envelope itself differs per user, not just record-level jitter.
func TestPersonalizeForDifferentSeedsDiverge(t *testing.T) {
	base := DefaultSaaSProfile()

	a := base.PersonalizeFor(0x1111111111111111)
	b := base.PersonalizeFor(0x2222222222222222)
	c := base.PersonalizeFor(0x3333333333333333)

	// At least one weight should differ between any two profiles.
	weightsDiffer := func(x, y *SiteProfile) bool {
		for i := range x.RecordSizeDistribution {
			if x.RecordSizeDistribution[i].Weight != y.RecordSizeDistribution[i].Weight {
				return true
			}
		}
		return false
	}
	if !weightsDiffer(a, b) {
		t.Error("seeds 0x11.. and 0x22.. produced identical weight distributions")
	}
	if !weightsDiffer(b, c) {
		t.Error("seeds 0x22.. and 0x33.. produced identical weight distributions")
	}

	// Burst ranges should also vary across at least one of the three.
	rangesDiffer := false
	for _, p := range []*SiteProfile{b, c} {
		if a.BurstPattern.RecordsPerBurst != p.BurstPattern.RecordsPerBurst ||
			a.BurstPattern.InterBurstPause != p.BurstPattern.InterBurstPause {
			rangesDiffer = true
			break
		}
	}
	if !rangesDiffer {
		t.Error("burst ranges identical across 3 different seeds — jitter not applied")
	}

	t.Logf("seed1 weights[0]=%.3f burst=%+v pause=%+v",
		a.RecordSizeDistribution[0].Weight, a.BurstPattern.RecordsPerBurst, a.BurstPattern.InterBurstPause)
	t.Logf("seed2 weights[0]=%.3f burst=%+v pause=%+v",
		b.RecordSizeDistribution[0].Weight, b.BurstPattern.RecordsPerBurst, b.BurstPattern.InterBurstPause)
	t.Logf("seed3 weights[0]=%.3f burst=%+v pause=%+v",
		c.RecordSizeDistribution[0].Weight, c.BurstPattern.RecordsPerBurst, c.BurstPattern.InterBurstPause)
}

// TestPersonalizeForValid verifies that personalized profiles still
// pass Validate(). This catches the most common breakage: weights not
// re-normalized to sum 1.0 after jitter, or ranges shifted out of TLS
// bounds.
func TestPersonalizeForValid(t *testing.T) {
	seeds := []uint64{
		0x1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xDEADBEEF, 0xCAFEBABE, 0xABCDEF0123456789,
	}
	presets := []*SiteProfile{
		DefaultBalancedProfile(),
		DefaultStealthProfile(),
		DefaultAggressiveProfile(),
		DefaultWordPressProfile(),
		DefaultLowPowerProfile(),
	}
	for _, preset := range presets {
		for _, seed := range seeds {
			personalized := preset.PersonalizeFor(seed)
			if err := personalized.Validate(); err != nil {
				t.Errorf("%s seed=0x%x: validate failed: %v", preset.Name, seed, err)
			}
		}
	}
}

// TestPersonalizeForZeroSeedBypass verifies that seed=0 returns the
// profile unchanged (same pointer). This is a deliberate escape hatch
// for tests and any caller that wants pristine profile semantics.
func TestPersonalizeForZeroSeedBypass(t *testing.T) {
	base := DefaultSaaSProfile()
	got := base.PersonalizeFor(0)
	if got != base {
		t.Errorf("PersonalizeFor(0) should return base unchanged, got new instance")
	}
}

// TestPersonalizeForWeightsSumToOne verifies the re-normalization
// invariant after jitter — Validate() requires |sum - 1.0| < 0.01.
func TestPersonalizeForWeightsSumToOne(t *testing.T) {
	base := DefaultSaaSProfile()
	for seed := uint64(1); seed < 100; seed++ {
		p := base.PersonalizeFor(seed)
		var total float64
		for _, b := range p.RecordSizeDistribution {
			total += b.Weight
		}
		if total < 0.99 || total > 1.01 {
			t.Errorf("seed=%d: weights sum to %f, expected ~1.0", seed, total)
		}
	}
}

func TestBurstPerClientVariation(t *testing.T) {
	p := DefaultSaaSProfile()

	// Two different clients should produce different bursts.
	b1, _ := p.GenerateBurst(1)
	b2, _ := p.GenerateBurst(2)

	if len(b1.RecordSizes) == len(b2.RecordSizes) {
		same := true
		for i := range b1.RecordSizes {
			if b1.RecordSizes[i] != b2.RecordSizes[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("two different seeds produced identical bursts — per-client randomization broken")
		}
	}
}

// TestSaaSDeploymentProfilesResolveByName guards the production failure
// that motivated the built-in twins: a share link naming "saas-stealth",
// "saas-fast" or "saas-max" (the deploy/profiles/ shapes the server side
// uses) must resolve to a struct, not fall through to the filesystem-path
// branch and die with "open saas-stealth: no such file or directory".
// Every alias spelling must resolve non-nil.
func TestSaaSDeploymentProfilesResolveByName(t *testing.T) {
	names := []string{
		"saas-stealth", "saas_stealth", "SAAS-STEALTH", " saas-stealth ",
		"saas-fast", "saas_fast", "SAAS-FAST",
		"saas-max", "saas_max", "SAAS-MAX", " saas-max ",
	}
	for _, n := range names {
		if p := BuiltInProfileByName(n); p == nil {
			t.Errorf("BuiltInProfileByName(%q) = nil, want non-nil", n)
		}
	}
}

// TestUnknownProfileNameStillNil confirms the resolver has not become a
// catch-all: an unrecognised name must return nil so the caller still
// falls back to LoadProfile / DefaultSaaSProfile.
func TestUnknownProfileNameStillNil(t *testing.T) {
	for _, n := range []string{"no-such-profile", "saas", "saas-stealthy", "fast", "max", "saas-maximum"} {
		// "saas" is a known alias for balanced; exclude it.
		if n == "saas" {
			continue
		}
		if p := BuiltInProfileByName(n); p != nil {
			t.Errorf("BuiltInProfileByName(%q) = %q, want nil", n, p.Name)
		}
	}
}

// TestSaaSProfilesNotAliasedToOthers guards the wrong-alias mistake: the
// deployment twins differ materially from the aggressive/stealth presets
// (buckets, records-per-burst, inter-burst pauses, concurrent streams), so
// substituting one for the other would put a different fingerprint on the
// wire than the server was configured with.
func TestSaaSProfilesNotAliasedToOthers(t *testing.T) {
	fast := DefaultSaaSFastProfile()
	if reflect.DeepEqual(fast, DefaultAggressiveProfile()) {
		t.Error("saas-fast is identical to aggressive — must not be aliased")
	}
	stealth := DefaultSaaSStealthProfile()
	if reflect.DeepEqual(stealth, DefaultStealthProfile()) {
		t.Error("saas-stealth is identical to stealth — must not be aliased")
	}
	// Spot-check the specific fields the task calls out, so a future edit
	// that accidentally converges them fails loudly with a clear reason.
	if fast.BurstPattern.RecordsPerBurst == DefaultAggressiveProfile().BurstPattern.RecordsPerBurst {
		t.Error("saas-fast records-per-burst matches aggressive (should be 34–76 vs 15–40)")
	}
	if fast.ConcurrentStreams == DefaultAggressiveProfile().ConcurrentStreams {
		t.Error("saas-fast concurrent streams match aggressive (should be 2–7 vs 4–16)")
	}
	maxp := DefaultSaaSMaxProfile()
	if reflect.DeepEqual(maxp, DefaultAggressiveProfile()) {
		t.Error("saas-max is identical to aggressive — must not be aliased")
	}
	if reflect.DeepEqual(maxp, fast) {
		t.Error("saas-max is identical to saas-fast — must not be aliased")
	}
	if maxp.BurstPattern.RecordsPerBurst == fast.BurstPattern.RecordsPerBurst {
		t.Error("saas-max records-per-burst matches saas-fast (should be 75–210 vs 34–76)")
	}
	if maxp.BurstPattern.InterBurstPause == fast.BurstPattern.InterBurstPause {
		t.Error("saas-max inter-burst pause matches saas-fast (should be 2–9ms vs 4–22ms)")
	}
}

// TestSaaSProfilesValid confirms the hand-written twins pass Validate()
// (weights sum to ~1, buckets in TLS bounds, ratio in range).
func TestSaaSProfilesValid(t *testing.T) {
	for _, p := range []*SiteProfile{DefaultSaaSStealthProfile(), DefaultSaaSFastProfile(), DefaultSaaSMaxProfile()} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: validate failed: %v", p.Name, err)
		}
	}
	// saas-stealth carries bypass_pause_cap: true in the JSON; make sure the
	// struct field followed, since long pauses are the point of that profile.
	if !DefaultSaaSStealthProfile().BypassPauseCap {
		t.Error("saas-stealth must set BypassPauseCap (bypass_pause_cap in JSON)")
	}
	if DefaultSaaSFastProfile().BypassPauseCap {
		t.Error("saas-fast must not set BypassPauseCap (absent in JSON)")
	}
	if DefaultSaaSMaxProfile().BypassPauseCap {
		t.Error("saas-max must not set BypassPauseCap (absent in JSON)")
	}
}

// TestSaaSProfilesMatchShippedJSON is the strongest form of the twin
// check: load the actual deploy/profiles/*.example.json files and
// deep-compare to the built-in constructors. If a bucket, range or ratio
// drifts between the shipped JSON and the Go twin, this fails — and the
// fix is the struct, not the test (the JSON is what the server uses).
func TestSaaSProfilesMatchShippedJSON(t *testing.T) {
	cases := []struct {
		path  string
		built *SiteProfile
	}{
		{"../../deploy/profiles/saas-stealth.example.json", DefaultSaaSStealthProfile()},
		{"../../deploy/profiles/saas-fast.example.json", DefaultSaaSFastProfile()},
		{"../../deploy/profiles/saas-max.example.json", DefaultSaaSMaxProfile()},
	}
	for _, tc := range cases {
		loaded, err := LoadProfile(tc.path)
		if err != nil {
			t.Fatalf("load %s: %v", tc.path, err)
		}
		if !reflect.DeepEqual(loaded, tc.built) {
			t.Errorf("built-in twin diverges from %s:\n loaded=%+v\n  built=%+v",
				tc.path, loaded, tc.built)
		}
	}
}

// TestResolveProfileDefaultCarriesTheTunnel pins what an endpoint that
// names no profile gets. It used to get DefaultSaaSProfile, whose burst
// budget capped the client's upstream half at ~0.2 MB/s — measured at
// 0.12 MB/s against the production server on 2026-09-09 while the same
// box managed 2.5 MB/s unshaped. Every default connection paid it, and
// the symptom users reported was "the internet barely works".
//
// The named presets must keep resolving to themselves: an operator who
// asks for "balanced" is asking for the slow shape on purpose.
func TestResolveProfileDefaultCarriesTheTunnel(t *testing.T) {
	got, err := resolveProfile("")
	if err != nil {
		t.Fatalf("resolveProfile(\"\"): %v", err)
	}
	if want := DefaultClientUpstreamProfile(); !reflect.DeepEqual(got, want) {
		t.Errorf("empty profile resolved to %q, want %q", got.Name, want.Name)
	}

	for name, want := range map[string]*SiteProfile{
		"balanced":          DefaultBalancedProfile(),
		"stealth":           DefaultStealthProfile(),
		"saas-fast":         DefaultSaaSFastProfile(),
		"server-downstream": DefaultServerDownstreamProfile(),
		"client-upstream":   DefaultClientUpstreamProfile(),
	} {
		got, err := resolveProfile(name)
		if err != nil {
			t.Fatalf("resolveProfile(%q): %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("resolveProfile(%q) = %q, want %q", name, got.Name, want.Name)
		}
	}

	if _, err := resolveProfile("no-such-profile.json"); err == nil {
		t.Error("unknown name that is not a readable file must fail, not silently default")
	}
}

// TestClientUpstreamProfileIsUsable guards the shape itself: a profile
// the transport falls back to has to pass the same validation an operator
// supplied JSON does, and its shaped path has to start where shaping
// starts. Buckets below minShapingThreshold spend the burst budget on
// records the shaper never emits — writes that small pass through
// untouched — which is exactly how the old default ended up modelling
// traffic it was not carrying.
func TestClientUpstreamProfileIsUsable(t *testing.T) {
	p := DefaultClientUpstreamProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("client upstream profile invalid: %v", err)
	}
	if p.BypassPauseCap {
		t.Error("client upstream must stay under the inline pause cap")
	}
	for _, b := range p.RecordSizeDistribution {
		if b.MinSize < minShapingThreshold {
			t.Errorf("bucket [%d, %d] starts below the %d-byte shaping threshold",
				b.MinSize, b.MaxSize, minShapingThreshold)
		}
	}
}
