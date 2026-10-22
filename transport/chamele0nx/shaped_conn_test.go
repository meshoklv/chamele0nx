package chamele0nx

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestShapedConnSplitsLargeWrites verifies that ShapedConn splits large
// writes into multiple TLS records matching the profile distribution,
// instead of producing uniform ~16KB records that DPI flags as VPN.
func TestShapedConnSplitsLargeWrites(t *testing.T) {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawConn, err := rawLn.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		tlsConn := tls.Server(rawConn, tlsCfg)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		io.Copy(io.Discard, tlsConn)
	}()

	rawConn, err := net.Dial("tcp", rawLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	interceptor := &tlsRecordInterceptor{conn: rawConn}
	clientCfg := &tls.Config{
		InsecureSkipVerify:          true,
		DynamicRecordSizingDisabled: true,
	}
	tlsConn := tls.Client(interceptor, clientCfg)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Clear handshake records.
	interceptor.mu.Lock()
	interceptor.records = nil
	interceptor.mu.Unlock()

	// Wrap with ShapedConn using default SaaS profile.
	profile := DefaultSaaSProfile()
	shaped := NewShapedConn(tlsConn, profile, 12345)

	// Write 32KB — simulating a large HTTP/2 DATA frame.
	// Without shaping: 2 records of 16KB.
	// With shaping: multiple records of varying sizes from profile.
	data := make([]byte, 32*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}

	n, err := shaped.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("short write: %d/%d", n, len(data))
	}

	time.Sleep(20 * time.Millisecond)

	interceptor.mu.Lock()
	records := make([]tlsRecord, len(interceptor.records))
	copy(records, interceptor.records)
	interceptor.mu.Unlock()

	var appRecords []tlsRecord
	for _, r := range records {
		if r.contentType == 0x17 { // application_data
			appRecords = append(appRecords, r)
		}
	}

	// With shaping, 32KB should produce at least 3 records (profile sizes
	// range from 64 to 16384, most are 200-5000 bytes).
	if len(appRecords) < 3 {
		t.Errorf("expected at least 3 shaped records for 32KB, got %d", len(appRecords))
	}

	// Verify not all records are max-sized (would indicate no shaping).
	allMax := true
	for _, r := range appRecords {
		if r.length != maxTLSRecord+tls13RecordOverhead {
			allMax = false
			break
		}
	}
	if allMax && len(appRecords) > 1 {
		t.Error("all records are max size — shaping not applied")
	}

	// Log record sizes for inspection.
	for i, r := range appRecords {
		payloadApprox := r.length - tls13RecordOverhead
		t.Logf("record %d: wire=%d, payload≈%d", i, r.length, payloadApprox)
	}
	t.Logf("PASS: 32KB split into %d shaped TLS records", len(appRecords))

	tlsConn.Close()
	wg.Wait()
}

// TestShapedConnPassesSmallWrites verifies that writes below
// minShapingThreshold pass through as a single TLS record (unshaped).
// This preserves natural HTTP/2 control frame sizes.
func TestShapedConnPassesSmallWrites(t *testing.T) {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawConn, err := rawLn.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		tlsConn := tls.Server(rawConn, tlsCfg)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		io.Copy(io.Discard, tlsConn)
	}()

	rawConn, err := net.Dial("tcp", rawLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	interceptor := &tlsRecordInterceptor{conn: rawConn}
	clientCfg := &tls.Config{
		InsecureSkipVerify:          true,
		DynamicRecordSizingDisabled: true,
	}
	tlsConn := tls.Client(interceptor, clientCfg)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	interceptor.mu.Lock()
	interceptor.records = nil
	interceptor.mu.Unlock()

	profile := DefaultSaaSProfile()
	shaped := NewShapedConn(tlsConn, profile, 12345)

	// Write 100 bytes — below minShapingThreshold (512).
	data := make([]byte, 100)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}

	n, err := shaped.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("short write: %d/%d", n, len(data))
	}

	time.Sleep(20 * time.Millisecond)

	interceptor.mu.Lock()
	records := make([]tlsRecord, len(interceptor.records))
	copy(records, interceptor.records)
	interceptor.mu.Unlock()

	var appRecords []tlsRecord
	for _, r := range records {
		if r.contentType == 0x17 {
			appRecords = append(appRecords, r)
		}
	}

	// Small write should produce exactly 1 record (pass-through).
	if len(appRecords) != 1 {
		t.Errorf("expected 1 record for small write, got %d", len(appRecords))
	} else {
		t.Logf("PASS: small write (%d bytes) → 1 TLS record (wire=%d)", len(data), appRecords[0].length)
	}

	tlsConn.Close()
	wg.Wait()
}

// TestShapedConnNilProfile verifies that nil profile = no shaping (pass-through).
func TestShapedConnNilProfile(t *testing.T) {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawConn, err := rawLn.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		tlsConn := tls.Server(rawConn, tlsCfg)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		io.Copy(io.Discard, tlsConn)
	}()

	rawConn, err := net.Dial("tcp", rawLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	interceptor := &tlsRecordInterceptor{conn: rawConn}
	clientCfg := &tls.Config{
		InsecureSkipVerify:          true,
		DynamicRecordSizingDisabled: true,
	}
	tlsConn := tls.Client(interceptor, clientCfg)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	interceptor.mu.Lock()
	interceptor.records = nil
	interceptor.mu.Unlock()

	// nil profile → pass-through, no shaping.
	shaped := NewShapedConn(tlsConn, nil, 12345)

	data := make([]byte, 8000)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}

	n, err := shaped.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("short write: %d/%d", n, len(data))
	}

	time.Sleep(20 * time.Millisecond)

	interceptor.mu.Lock()
	records := make([]tlsRecord, len(interceptor.records))
	copy(records, interceptor.records)
	interceptor.mu.Unlock()

	var appRecords []tlsRecord
	for _, r := range records {
		if r.contentType == 0x17 {
			appRecords = append(appRecords, r)
		}
	}

	// Without shaping, 8000 bytes should be 1 record.
	if len(appRecords) != 1 {
		t.Errorf("expected 1 record with nil profile, got %d", len(appRecords))
	} else {
		t.Logf("PASS: nil profile → 1 unshaped TLS record (wire=%d)", appRecords[0].length)
	}

	tlsConn.Close()
	wg.Wait()
}

// timedWriteRecord captures one Write call with wall-clock timestamp.
// Used by TestShapedConnInjectsBurstPause to observe inter-record timing.
type timedWriteRecord struct {
	size int
	at   time.Time
}

// timedMockConn is a no-op net.Conn that records every Write with a
// monotonic timestamp. No actual I/O, no TLS, no framing — the point is
// to isolate ShapedConn's burst-pause scheduling from everything else.
type timedMockConn struct {
	mu     sync.Mutex
	writes []timedWriteRecord
}

func (c *timedMockConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, timedWriteRecord{size: len(p), at: time.Now()})
	c.mu.Unlock()
	return len(p), nil
}

func (c *timedMockConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *timedMockConn) Close() error                       { return nil }
func (c *timedMockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *timedMockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *timedMockConn) SetDeadline(t time.Time) error      { return nil }
func (c *timedMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *timedMockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestShapedConnInjectsBurstPause verifies that the v2 BurstShaper in
// ShapedConn.Write actually sleeps between bursts according to the
// profile's InterBurstPause. With RecordsPerBurst={3,3} and a 50ms pause,
// records must group into triplets with ≥~40ms gaps between groups and
// effectively zero gap within a group.
//
// This test exists because in an earlier revision the burst-pause code
// was a dead letter: the pause was implemented in a helper that the data
// path never called, so writes streamed back to back with no timing
// shaping at all.
func TestShapedConnInjectsBurstPause(t *testing.T) {
	// Tight deterministic profile: exactly 3 records per burst, exactly
	// 50ms between bursts, record size in a narrow band so we get a
	// predictable number of total records for the test payload.
	profile := &SiteProfile{
		Name:    "test-burst-pause",
		Version: 1,
		RecordSizeDistribution: []SizeBucket{
			{MinSize: 500, MaxSize: 500, Weight: 1.0},
		},
		BurstPattern: BurstPattern{
			RecordsPerBurst:  Range{Min: 3, Max: 3},
			BurstDuration:    DurationRange{Min: 100 * time.Millisecond, Max: 100 * time.Millisecond},
			InterBurstPause:  DurationRange{Min: 50 * time.Millisecond, Max: 50 * time.Millisecond},
			InterRecordDelay: DurationRange{Min: 0, Max: 0},
		},
		SessionProfile: SessionProfile{
			Duration:             DurationRange{Min: 1 * time.Minute, Max: 1 * time.Minute},
			BurstsPerSession:     Range{Min: 1, Max: 10},
			TotalBytesPerSession: Range{Min: 1000, Max: 1_000_000},
		},
		UploadDownloadRatio: 0.1,
		ConcurrentStreams:   Range{Min: 1, Max: 1},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("profile.Validate: %v", err)
	}

	mock := &timedMockConn{}
	shaped := NewShapedConn(mock, profile, 0x1234)

	// 5000 bytes / ~500-byte records (± jitter) → ~10-15 records → 3-5 bursts.
	// At RecordsPerBurst=3 and 50ms pause, 10 records = 3 full bursts + 1 partial
	// = 3 pauses = ≥150ms. We'll use 5000 bytes as a compromise between fast
	// test execution and enough samples to observe the pattern.
	data := make([]byte, 5000)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}

	start := time.Now()
	n, err := shaped.Write(data)
	total := time.Since(start)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("short write: %d/%d", n, len(data))
	}

	mock.mu.Lock()
	writes := make([]timedWriteRecord, len(mock.writes))
	copy(writes, mock.writes)
	mock.mu.Unlock()

	if len(writes) < 6 {
		t.Fatalf("expected ≥6 shaped records for 5000 bytes, got %d", len(writes))
	}

	// With RecordsPerBurst=3 and 50ms pause, the expected total wall-clock
	// time for N records is at least ⌊(N-1)/3⌋ * 50ms. Allow 20% tolerance
	// downward for scheduling jitter.
	numPauses := (len(writes) - 1) / 3
	expectedMin := time.Duration(numPauses) * 40 * time.Millisecond // 50ms * 0.8
	if total < expectedMin {
		t.Errorf("burst pauses not applied: total %v < expected min %v (records=%d, pauses=%d)",
			total, expectedMin, len(writes), numPauses)
	}

	// Inspect intra-burst vs inter-burst gaps. Within a burst (records
	// 1→2, 2→3 of a triplet) the gap should be near zero. Between bursts
	// (record 3→4, 6→7, ...) it should be ≥40ms.
	var interBurstGaps, intraBurstGaps []time.Duration
	for i := 1; i < len(writes); i++ {
		gap := writes[i].at.Sub(writes[i-1].at)
		if i%3 == 0 {
			// i=3,6,9,... → boundary between bursts.
			interBurstGaps = append(interBurstGaps, gap)
		} else {
			intraBurstGaps = append(intraBurstGaps, gap)
		}
	}

	for i, g := range interBurstGaps {
		if g < 40*time.Millisecond {
			t.Errorf("inter-burst gap #%d too short: %v (expected ≥40ms)", i, g)
		}
	}
	for i, g := range intraBurstGaps {
		if g > 20*time.Millisecond {
			t.Errorf("intra-burst gap #%d too long: %v (expected ≤20ms, no pause inside burst)", i, g)
		}
	}

	t.Logf("PASS: %d records, %d bursts, total %v, inter-burst gaps %v, intra-burst gaps %v",
		len(writes), numPauses+1, total, interBurstGaps, intraBurstGaps)
}

// TestShapedConnNaturalGapDeduction verifies that when an idle period
// between ShapedConn.Write calls already exceeds the sampled burst pause,
// the shaper does NOT add additional sleep. This keeps idle/interactive
// traffic unstalled — the pause is only injected when the HTTP/2 layer
// is actively streaming.
//
// Test shape is picked carefully so each Write produces exactly ONE
// record (RecordsPerBurst=1, record size ≥ payload). This isolates the
// natural-gap check at the very start of the second Write — if we let
// multiple records fit per Write we'd also trigger mid-Write burst pauses
// which are unrelated to the gap-deduction behavior under test.
func TestShapedConnNaturalGapDeduction(t *testing.T) {
	profile := &SiteProfile{
		Name:    "test-natural-gap",
		Version: 1,
		RecordSizeDistribution: []SizeBucket{
			// Record size much larger than the test payload so each
			// Write produces exactly 1 record even with ±25% jitter.
			{MinSize: 2000, MaxSize: 2000, Weight: 1.0},
		},
		BurstPattern: BurstPattern{
			// Single-record bursts: any Write that emits at least one
			// record fills exactly one burst, so the next Write's first
			// maybeBurstPause call hits the pause-injection branch.
			RecordsPerBurst:  Range{Min: 1, Max: 1},
			BurstDuration:    DurationRange{Min: 100 * time.Millisecond, Max: 100 * time.Millisecond},
			InterBurstPause:  DurationRange{Min: 80 * time.Millisecond, Max: 80 * time.Millisecond},
			InterRecordDelay: DurationRange{Min: 0, Max: 0},
		},
		SessionProfile: SessionProfile{
			Duration:             DurationRange{Min: 1 * time.Minute, Max: 1 * time.Minute},
			BurstsPerSession:     Range{Min: 1, Max: 10},
			TotalBytesPerSession: Range{Min: 1000, Max: 1_000_000},
		},
		UploadDownloadRatio: 0.1,
		ConcurrentStreams:   Range{Min: 1, Max: 1},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("profile.Validate: %v", err)
	}

	mock := &timedMockConn{}
	shaped := NewShapedConn(mock, profile, 0x5678)

	// 600 bytes: above minShapingThreshold (512) so shaping kicks in,
	// and below the minimum jittered record size (≥1500) so exactly 1
	// record is emitted per Write.
	payload := make([]byte, 600)
	rand.Read(payload)

	// First Write — fills one burst.
	if _, err := shaped.Write(payload); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Idle longer than the configured pause (80ms). 150ms gives 70ms
	// slack. The next Write should NOT sleep at all; the natural gap
	// has already paid the timing cost.
	time.Sleep(150 * time.Millisecond)

	start := time.Now()
	if _, err := shaped.Write(payload); err != nil {
		t.Fatalf("second write: %v", err)
	}
	elapsed := time.Since(start)

	mock.mu.Lock()
	writeCount := len(mock.writes)
	mock.mu.Unlock()
	if writeCount != 2 {
		t.Fatalf("expected 2 records total (1 per Write), got %d — record size/payload sizing is wrong for this test", writeCount)
	}

	// Second write should complete quickly — natural gap already > pause.
	// Allow 25ms slack for scheduling jitter on busy CI.
	if elapsed > 25*time.Millisecond {
		t.Errorf("natural-gap deduction failed: second Write took %v (expected <25ms)", elapsed)
	}

	t.Logf("PASS: natural-gap deduction — second write after 150ms idle took %v", elapsed)
}

// TestShapedConnConnectionState verifies ConnectionState delegation works
// (required for HTTP/2 transport to recognize TLS connection).
func TestShapedConnConnectionState(t *testing.T) {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	shaped := NewShapedConn(conn, nil, 0)

	// ConnectionState should be delegated to inner tls.Conn.
	state := shaped.ConnectionState()
	if !state.HandshakeComplete {
		t.Error("ConnectionState: handshake not complete")
	}
	if state.Version == 0 {
		t.Error("ConnectionState: TLS version is 0")
	}

	t.Logf("PASS: ConnectionState delegated (version=0x%04x, cipher=0x%04x)",
		state.Version, state.CipherSuite)

	conn.Close()
	wg.Wait()
}

// TestShapedConnProfileThroughput measures the effective wall-clock
// throughput of ShapedConn for each built-in profile by pushing a
// fixed payload through a no-op net.Conn (timedMockConn, no TCP/TLS
// overhead) and dividing by elapsed time.
//
// Purpose: catch profile combinations whose burst-pause budget would
// cripple the server's downstream path before they reach a deployment.
// It was added after field testing in April 2026, where shaping the
// downstream with DefaultSaaSProfile cut throughput on a test handset
// from 9.4 Mbps to 0.6-2.3 Mbps (a 4-10× slowdown) and forced a rollback.
//
// The test does NOT assert absolute Mbps numbers — real TCP/TLS ceiling
// is lower than what the mock reports and depends on RTT + MSS. It only
// asserts that:
//   - Stealth and SaaS are **intentionally** slow (stealth is the only
//     profile with BypassPauseCap=true; SaaS deliberately pauses).
//   - ServerDownstream and Aggressive are **at least 4× faster** than
//     SaaS, proving the new profile actually escapes the pause budget
//     that tanked the VPS deploy.
//
// Numbers are logged for visibility when debugging profile tuning.
func TestShapedConnProfileThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput measurement skipped in short mode")
	}

	// 128 KB — ~1s on SaaS (slowest in this set), ~0.1s on Aggressive /
	// ServerDownstream. Stealth and LowPower are excluded from the sweep
	// because their intentional long pauses would stretch the test to
	// minutes of wall-clock time — they serve a different niche (explicit
	// throttle-tolerant mode) and don't contribute to the SaaS-vs-
	// ServerDownstream comparison this test exists to guard.
	const payloadSize = 128 * 1024

	cases := []struct {
		name    string
		profile *SiteProfile
	}{
		{"SaaS", DefaultSaaSProfile()},
		{"Aggressive", DefaultAggressiveProfile()},
		{"ServerDownstream", DefaultServerDownstreamProfile()},
		{"ClientUpstream", DefaultClientUpstreamProfile()},
	}

	// Each profile is measured several times and the FASTEST run is kept.
	// This is a wall-clock measurement, and wall-clock noise on a shared
	// machine is one-sided: another process can only ever make a run slower,
	// never faster. Taking a single sample let a scheduling stall inside the
	// fast profiles collapse the ratio and fail the test — observed once in
	// ten runs on a loaded machine, which on a CI runner means CI goes red
	// for no reason. The fastest of several samples is the closest thing to
	// an interference-free measurement, and the property under test — that
	// the pause budget differs by a wide margin — is unchanged.
	const samples = 5

	results := make(map[string]float64, len(cases))
	for _, tc := range cases {
		best := 0.0
		var bestElapsed time.Duration
		for i := 0; i < samples; i++ {
			mock := &timedMockConn{}
			shaped := NewShapedConn(mock, tc.profile, 0) // seed=0 → no personalization

			data := make([]byte, payloadSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("rand: %v", err)
			}

			start := time.Now()
			n, err := shaped.Write(data)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("%s: write: %v", tc.name, err)
			}
			if n != len(data) {
				t.Fatalf("%s: short write: %d/%d", tc.name, n, len(data))
			}

			// A run too fast to measure is faster than anything this test
			// needs to distinguish; floor it so the ratio stays a number.
			if elapsed < time.Microsecond {
				elapsed = time.Microsecond
			}
			if mbps := float64(n*8) / elapsed.Seconds() / 1_000_000.0; mbps > best {
				best, bestElapsed = mbps, elapsed
			}
		}
		results[tc.name] = best
		t.Logf("%-18s %8.2f Mbps (best of %d, %d bytes in %s)",
			tc.name, best, samples, payloadSize, bestElapsed.Round(time.Millisecond))
	}

	// Assertion: ServerDownstream must be materially faster than SaaS.
	// If this fails, the new profile's pause budget is not actually
	// shorter in practice (e.g. sampled pauses hit the clamp or the
	// RecordsPerBurst range is too low).
	const minSpeedup = 4.0
	if results["ServerDownstream"] < results["SaaS"]*minSpeedup {
		t.Errorf("ServerDownstream (%.2f Mbps) not at least %.0f× faster than SaaS (%.2f Mbps)",
			results["ServerDownstream"], minSpeedup, results["SaaS"])
	}

	// Assertion: Aggressive must also beat SaaS by the same margin.
	// Catches regressions in the Aggressive profile during retuning.
	if results["Aggressive"] < results["SaaS"]*minSpeedup {
		t.Errorf("Aggressive (%.2f Mbps) not at least %.0f× faster than SaaS (%.2f Mbps)",
			results["Aggressive"], minSpeedup, results["SaaS"])
	}

	// Assertion: the client's upstream half must escape the same pause
	// budget. It is the profile a connection falls back to when the
	// endpoint names none, so a regression here is not a tuning detail —
	// it is every default connection back at 0.12 MB/s upstream, which is
	// what "the internet barely works" looked like in September 2026.
	if results["ClientUpstream"] < results["SaaS"]*minSpeedup {
		t.Errorf("ClientUpstream (%.2f Mbps) not at least %.0f× faster than SaaS (%.2f Mbps)",
			results["ClientUpstream"], minSpeedup, results["SaaS"])
	}
}

// TestShapedConnGatedUntilArmed verifies the server-side gate: a
// connection built with newGatedShapedConn passes writes through
// untouched until Arm is called, and only then splits them per the
// profile. This is what keeps an unauthenticated probe from ever
// observing the shaping envelope — shaping switches on only after the
// tunnel handler authenticates the client. Before the gate existed this
// connection would have shaped from the very first write.
func TestShapedConnGatedUntilArmed(t *testing.T) {
	profile := &SiteProfile{
		Name:    "test-gate",
		Version: 1,
		RecordSizeDistribution: []SizeBucket{
			{MinSize: 200, MaxSize: 200, Weight: 1.0},
		},
		BurstPattern: BurstPattern{
			RecordsPerBurst:  Range{Min: 1000, Max: 1000},
			BurstDuration:    DurationRange{Min: 0, Max: 0},
			InterBurstPause:  DurationRange{Min: 0, Max: 0},
			InterRecordDelay: DurationRange{Min: 0, Max: 0},
		},
	}

	mock := &timedMockConn{}
	sc := newGatedShapedConn(mock, profile, 0x99)

	data := make([]byte, 2000) // well above minShapingThreshold
	if _, err := sc.Write(data); err != nil {
		t.Fatalf("write (un-armed): %v", err)
	}

	mock.mu.Lock()
	unarmed := len(mock.writes)
	mock.mu.Unlock()
	if unarmed != 1 {
		t.Fatalf("un-armed shaper must pass a large write through as one record, got %d records", unarmed)
	}

	// Arm and write again: now the same size must be split into many
	// ~200-byte records.
	sc.Arm()
	if _, err := sc.Write(data); err != nil {
		t.Fatalf("write (armed): %v", err)
	}

	mock.mu.Lock()
	armed := len(mock.writes) - unarmed
	mock.mu.Unlock()
	if armed < 5 {
		t.Fatalf("armed shaper must split a 2000-byte write into many records, got %d", armed)
	}
}

// TestBurstPauseTruncatedBeforeSampling guards the fix for the 250ms
// point mass. The old sampler drew uniformly from the profile's full
// [min,max] and then clamped the result down to maxBurstPauseInWrite,
// which collected every over-cap draw onto that one exact value — for a
// profile whose max sits well above the cap, most draws landed there.
// The sampler now truncates the range to the cap BEFORE drawing (and
// draws log-uniform), so no value dominates. This test would fire on the
// old clamp-after-sample behaviour.
func TestBurstPauseTruncatedBeforeSampling(t *testing.T) {
	profile := &SiteProfile{
		Name:    "test-pause-truncation",
		Version: 1,
		RecordSizeDistribution: []SizeBucket{
			{MinSize: 500, MaxSize: 500, Weight: 1.0},
		},
		BurstPattern: BurstPattern{
			RecordsPerBurst: Range{Min: 1, Max: 1},
			// Max (2s) sits far above maxBurstPauseInWrite (250ms), so
			// the old clamp would have piled ~90% of draws onto 250ms.
			InterBurstPause:  DurationRange{Min: 50 * time.Millisecond, Max: 2 * time.Second},
			InterRecordDelay: DurationRange{Min: 0, Max: 0},
		},
		// BypassPauseCap stays false: the cap must apply as a bound.
	}

	sc := NewShapedConn(&timedMockConn{}, profile, 0x1)

	const n = 2000
	atCap := 0
	distinct := make(map[time.Duration]int, n)
	for i := 0; i < n; i++ {
		d := sc.nextBurstPause()
		if d < 50*time.Millisecond || d > maxBurstPauseInWrite {
			t.Fatalf("pause %v out of truncated range [50ms, %v]", d, maxBurstPauseInWrite)
		}
		if d == maxBurstPauseInWrite {
			atCap++
		}
		distinct[d]++
	}

	// With clamp-after-sample this fraction was ~0.9; with truncation
	// before sampling it should be negligible.
	if atCap > n/20 {
		t.Fatalf("point mass at the cap: %d/%d draws landed exactly on %v — "+
			"looks like clamp-after-sample regressed", atCap, n, maxBurstPauseInWrite)
	}
	if len(distinct) < n/2 {
		t.Fatalf("pause distribution too concentrated: only %d distinct values in %d draws", len(distinct), n)
	}
}
