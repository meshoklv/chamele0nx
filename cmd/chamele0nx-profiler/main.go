// chamele0nx-profiler captures TLS record metadata from real websites to create
// traffic profiles for Chamele0nX Transport. It connects to a target site,
// browses several pages, and records the TLS record sizes and timing.
//
// Usage:
//
//	chamele0nx-profiler -target https://app.example.com -pages 10 -out profile.json
//
// The output profile.json can be loaded by Chamele0nX Transport to shape VPN
// traffic so it matches the target site's TLS fingerprint at the record level.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/meshoklv/chamele0nx/transport/chamele0nx"
)

func main() {
	target := flag.String("target", "", "Target URL (e.g., https://app.example.com)")
	pages := flag.Int("pages", 10, "Number of page requests to simulate")
	output := flag.String("out", "profile.json", "Output profile path")
	name := flag.String("name", "", "Profile name (defaults to hostname)")
	flag.Parse()
	exitIfVersionRequested("chamele0nx-profiler")

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	u, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("invalid target URL: %v", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	if *name == "" {
		*name = fmt.Sprintf("profile-%s", host)
	}

	log.Printf("Profiling %s (%d page requests)...", addr, *pages)

	// Capture TLS records while browsing the target site.
	records, bursts := profileSite(addr, host, u.String(), *pages)

	log.Printf("Captured %d TLS records in %d bursts", len(records), len(bursts))

	// Build profile from captured data.
	profile := buildProfile(*name, records, bursts)

	// Validate.
	if err := profile.Validate(); err != nil {
		log.Fatalf("generated profile invalid: %v", err)
	}

	// Write output.
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	if err := os.WriteFile(*output, data, 0o600); err != nil {
		log.Fatalf("write: %v", err)
	}

	log.Printf("Profile written to %s", *output)
	printProfileSummary(profile)
}

// capturedRecord is a single TLS record observed on the wire.
type capturedRecord struct {
	Size      int           // payload size (excluding 5-byte header)
	Timestamp time.Time     // when the record was seen
	Direction string        // "tx" or "rx"
	Gap       time.Duration // time since previous record
}

// capturedBurst is a group of records sent close together (page load).
type capturedBurst struct {
	Records  []capturedRecord
	Duration time.Duration
	Gap      time.Duration // pause before this burst
}

// profileSite connects to a real site and captures TLS record metadata.
//
// It returns no error: a page load that fails is logged and skipped so a
// single flaky request does not discard a whole profiling run. If every page
// fails the returned slices are empty, which the caller sees in the captured
// record count.
func profileSite(addr, sni, targetURL string, numPages int) ([]capturedRecord, []capturedBurst) {
	var allRecords []capturedRecord
	var allBursts []capturedBurst

	for i := 0; i < numPages; i++ {
		records, err := capturePageLoad(addr, sni, targetURL)
		if err != nil {
			log.Printf("page %d/%d failed: %v", i+1, numPages, err)
			continue
		}

		burstRecords := make([]capturedRecord, len(records))
		copy(burstRecords, records)

		var burstDuration time.Duration
		if len(records) > 1 {
			burstDuration = records[len(records)-1].Timestamp.Sub(records[0].Timestamp)
		}

		var gap time.Duration
		if len(allRecords) > 0 && len(records) > 0 {
			gap = records[0].Timestamp.Sub(allRecords[len(allRecords)-1].Timestamp)
		}

		allBursts = append(allBursts, capturedBurst{
			Records:  burstRecords,
			Duration: burstDuration,
			Gap:      gap,
		})

		allRecords = append(allRecords, records...)
		log.Printf("page %d/%d: %d records, burst %v", i+1, numPages, len(records), burstDuration)

		// Simulate reading pause (2-10s like real user).
		if i < numPages-1 {
			time.Sleep(2*time.Second + time.Duration(i%5)*time.Second)
		}
	}

	return allRecords, allBursts
}

// capturePageLoad makes one HTTP request and captures TLS record sizes.
func capturePageLoad(addr, sni, targetURL string) ([]capturedRecord, error) {
	// Dial TCP, wrap with TLS interceptor to capture record sizes.
	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	interceptor := newTLSInterceptor(tcpConn)

	tlsConn := tls.Client(interceptor, &tls.Config{
		ServerName:                  sni,
		NextProtos:                  []string{"h2", "http/1.1"},
		DynamicRecordSizingDisabled: true,
	})

	if err := tlsConn.Handshake(); err != nil {
		// Handshake failed, so the TCP connection is useless; the caller
		// acts on the handshake error, not on a close failure.
		_ = tcpConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// Clear handshake records.
	interceptor.mu.Lock()
	interceptor.records = nil
	interceptor.mu.Unlock()

	// Make HTTP request.
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return tlsConn, nil
			},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("http get: %w", err)
	}
	// Drain and discard the body: this tool only cares about the sizes of
	// the TLS records the interceptor saw, never about the content. A read
	// or close failure just means fewer records were captured, which shows
	// up in the returned slice.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_ = tlsConn.Close()

	// Collect captured records.
	interceptor.mu.Lock()
	defer interceptor.mu.Unlock()

	var result []capturedRecord
	var prevTime time.Time

	for _, r := range interceptor.records {
		if r.contentType != 0x17 { // application_data only
			continue
		}
		var gap time.Duration
		if !prevTime.IsZero() {
			gap = r.timestamp.Sub(prevTime)
		}
		result = append(result, capturedRecord{
			Size:      r.length,
			Timestamp: r.timestamp,
			Direction: r.direction,
			Gap:       gap,
		})
		prevTime = r.timestamp
	}

	return result, nil
}

// buildProfile constructs a SiteProfile from captured records.
func buildProfile(name string, records []capturedRecord, bursts []capturedBurst) *chamele0nx.SiteProfile {
	// Build record size distribution.
	var rxSizes []int
	for _, r := range records {
		if r.Direction == "rx" {
			rxSizes = append(rxSizes, r.Size)
		}
	}
	if len(rxSizes) == 0 {
		// Fallback: use all records.
		for _, r := range records {
			rxSizes = append(rxSizes, r.Size)
		}
	}

	distribution := buildDistribution(rxSizes)

	// Burst statistics.
	var recordsPerBurst []int
	var burstDurations []time.Duration
	var interBurstPauses []time.Duration

	for _, b := range bursts {
		recordsPerBurst = append(recordsPerBurst, len(b.Records))
		burstDurations = append(burstDurations, b.Duration)
		if b.Gap > 0 {
			interBurstPauses = append(interBurstPauses, b.Gap)
		}
	}

	// Inter-record delays within bursts.
	var interRecordDelays []time.Duration
	for _, b := range bursts {
		for i := 1; i < len(b.Records); i++ {
			d := b.Records[i].Timestamp.Sub(b.Records[i-1].Timestamp)
			interRecordDelays = append(interRecordDelays, d)
		}
	}

	// Upload/download ratio.
	var txBytes, rxBytes int
	for _, r := range records {
		if r.Direction == "tx" {
			txBytes += r.Size
		} else {
			rxBytes += r.Size
		}
	}
	ratio := 0.1 // default
	if rxBytes > 0 {
		ratio = float64(txBytes) / float64(rxBytes)
		if ratio > 1 {
			ratio = 1
		}
		if ratio < 0.01 {
			ratio = 0.01
		}
	}

	return &chamele0nx.SiteProfile{
		Name:                   name,
		Version:                1,
		RecordSizeDistribution: distribution,
		BurstPattern: chamele0nx.BurstPattern{
			RecordsPerBurst:  intRange(recordsPerBurst, 5, 15),
			BurstDuration:    durationRange(burstDurations, 500*time.Millisecond, 2*time.Second),
			InterBurstPause:  durationRange(interBurstPauses, 2*time.Second, 30*time.Second),
			InterRecordDelay: durationRange(interRecordDelays, 0, 50*time.Millisecond),
		},
		SessionProfile: chamele0nx.SessionProfile{
			Duration:             chamele0nx.DurationRange{Min: 3 * time.Minute, Max: 15 * time.Minute},
			BurstsPerSession:     chamele0nx.Range{Min: 5, Max: 30},
			TotalBytesPerSession: chamele0nx.Range{Min: 500_000, Max: 10_000_000},
		},
		UploadDownloadRatio: ratio,
		ConcurrentStreams:   chamele0nx.Range{Min: 1, Max: 6},
	}
}

// buildDistribution creates histogram buckets from observed sizes.
func buildDistribution(sizes []int) []chamele0nx.SizeBucket {
	if len(sizes) == 0 {
		return chamele0nx.DefaultSaaSProfile().RecordSizeDistribution
	}

	sort.Ints(sizes)

	// Fixed bucket boundaries matching common TLS record patterns.
	boundaries := []int{64, 200, 800, 2000, 5000, 10000, 16384}
	buckets := make([]chamele0nx.SizeBucket, len(boundaries))

	for i, max := range boundaries {
		min := 64
		if i > 0 {
			min = boundaries[i-1]
		}
		buckets[i] = chamele0nx.SizeBucket{MinSize: min, MaxSize: max}
	}

	// Count sizes in each bucket.
	total := float64(len(sizes))
	for _, s := range sizes {
		for i := range buckets {
			if s >= buckets[i].MinSize && s <= buckets[i].MaxSize {
				buckets[i].Weight++
				break
			}
		}
	}

	// Normalize weights.
	for i := range buckets {
		buckets[i].Weight /= total
	}

	// Remove empty buckets, ensure weights sum to 1.
	var result []chamele0nx.SizeBucket
	var totalWeight float64
	for _, b := range buckets {
		if b.Weight > 0 {
			result = append(result, b)
			totalWeight += b.Weight
		}
	}

	if len(result) == 0 {
		return chamele0nx.DefaultSaaSProfile().RecordSizeDistribution
	}

	// Adjust last bucket to make weights sum to exactly 1.
	if totalWeight > 0 && totalWeight != 1.0 {
		result[len(result)-1].Weight += 1.0 - totalWeight
	}

	return result
}

func intRange(vals []int, defaultMin, defaultMax int) chamele0nx.Range {
	if len(vals) == 0 {
		return chamele0nx.Range{Min: defaultMin, Max: defaultMax}
	}
	sort.Ints(vals)
	return chamele0nx.Range{
		Min: max(1, vals[len(vals)*5/100]), // 5th percentile
		Max: vals[len(vals)*95/100],        // 95th percentile
	}
}

func durationRange(vals []time.Duration, defaultMin, defaultMax time.Duration) chamele0nx.DurationRange {
	if len(vals) == 0 {
		return chamele0nx.DurationRange{Min: defaultMin, Max: defaultMax}
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return chamele0nx.DurationRange{
		Min: vals[len(vals)*5/100],  // 5th percentile
		Max: vals[len(vals)*95/100], // 95th percentile
	}
}

func printProfileSummary(p *chamele0nx.SiteProfile) {
	fmt.Printf("\n=== Profile: %s ===\n", p.Name)
	fmt.Printf("Record size distribution:\n")
	for _, b := range p.RecordSizeDistribution {
		bar := ""
		for i := 0; i < int(b.Weight*50); i++ {
			bar += "#"
		}
		fmt.Printf("  %5d - %5d: %5.1f%% %s\n", b.MinSize, b.MaxSize, b.Weight*100, bar)
	}
	fmt.Printf("Burst pattern:\n")
	fmt.Printf("  Records per burst: %d - %d\n", p.BurstPattern.RecordsPerBurst.Min, p.BurstPattern.RecordsPerBurst.Max)
	fmt.Printf("  Burst duration:    %v - %v\n", p.BurstPattern.BurstDuration.Min, p.BurstPattern.BurstDuration.Max)
	fmt.Printf("  Inter-burst pause: %v - %v\n", p.BurstPattern.InterBurstPause.Min, p.BurstPattern.InterBurstPause.Max)
	fmt.Printf("Upload/download ratio: %.2f\n", p.UploadDownloadRatio)
}

// --- TLS record interceptor (same approach as shaper_test.go) ---

type rawTLSRecord struct {
	contentType uint8
	length      int
	timestamp   time.Time
	direction   string // "tx" or "rx"
}

type tlsInterceptor struct {
	conn    net.Conn
	mu      sync.Mutex
	records []rawTLSRecord
	txBuf   []byte
	rxBuf   []byte
}

func newTLSInterceptor(conn net.Conn) *tlsInterceptor {
	return &tlsInterceptor{conn: conn}
}

func (t *tlsInterceptor) Write(b []byte) (int, error) {
	t.mu.Lock()
	t.txBuf = append(t.txBuf, b...)
	t.parseTLSRecords(t.txBuf, "tx")
	t.mu.Unlock()
	return t.conn.Write(b)
}

func (t *tlsInterceptor) Read(b []byte) (int, error) {
	n, err := t.conn.Read(b)
	if n > 0 {
		t.mu.Lock()
		t.rxBuf = append(t.rxBuf, b[:n]...)
		t.parseTLSRecords(t.rxBuf, "rx")
		t.mu.Unlock()
	}
	return n, err
}

func (t *tlsInterceptor) parseTLSRecords(buf []byte, dir string) {
	for len(buf) >= 5 {
		contentType := buf[0]
		if contentType < 0x14 || contentType > 0x19 {
			if dir == "tx" {
				t.txBuf = t.txBuf[1:]
			} else {
				t.rxBuf = t.rxBuf[1:]
			}
			buf = buf[1:]
			continue
		}
		length := int(binary.BigEndian.Uint16(buf[3:5]))
		if length > 16384+256 {
			if dir == "tx" {
				t.txBuf = t.txBuf[1:]
			} else {
				t.rxBuf = t.rxBuf[1:]
			}
			buf = buf[1:]
			continue
		}
		totalLen := 5 + length
		if len(buf) < totalLen {
			break
		}
		t.records = append(t.records, rawTLSRecord{
			contentType: contentType,
			length:      length,
			timestamp:   time.Now(),
			direction:   dir,
		})
		buf = buf[totalLen:]
	}
	if dir == "tx" {
		t.txBuf = buf
	} else {
		t.rxBuf = buf
	}
}

func (t *tlsInterceptor) Close() error                       { return t.conn.Close() }
func (t *tlsInterceptor) LocalAddr() net.Addr                { return t.conn.LocalAddr() }
func (t *tlsInterceptor) RemoteAddr() net.Addr               { return t.conn.RemoteAddr() }
func (t *tlsInterceptor) SetDeadline(d time.Time) error      { return t.conn.SetDeadline(d) }
func (t *tlsInterceptor) SetReadDeadline(d time.Time) error  { return t.conn.SetReadDeadline(d) }
func (t *tlsInterceptor) SetWriteDeadline(d time.Time) error { return t.conn.SetWriteDeadline(d) }

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Ensure math is used.
var _ = math.MaxFloat64
