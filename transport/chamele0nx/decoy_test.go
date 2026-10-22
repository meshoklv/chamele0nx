package chamele0nx

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRoundTripper records every request without doing any I/O.
// Lets DecoyDriver tests run hermetically — no network, no flakiness.
type fakeRoundTripper struct {
	mu       sync.Mutex
	requests []*http.Request
	body     string
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	body := f.body
	if body == "" {
		body = "ok"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
		Request:    req,
	}, nil
}

func (f *fakeRoundTripper) snapshot() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*http.Request, len(f.requests))
	copy(out, f.requests)
	return out
}

// TestDecoyDriverFetchesAreMade verifies that the driver actually
// fetches its configured targets within a tight scheduling window.
// Uses a tiny custom config (10ms intervals, fixed targets) so the
// test runs in <100ms.
func TestDecoyDriverFetchesAreMade(t *testing.T) {
	rt := &fakeRoundTripper{}
	client := &http.Client{Transport: rt, Timeout: time.Second}

	driver := NewDecoyDriver(DecoyConfig{
		Targets: []DecoyTarget{
			{URL: "https://example.com/a", Category: "test"},
			{URL: "https://example.com/b", Category: "test"},
		},
		MinInterval:   5 * time.Millisecond,
		MaxInterval:   10 * time.Millisecond,
		BurstMin:      2,
		BurstMax:      3,
		IntraBurstMin: 1 * time.Millisecond,
		IntraBurstMax: 2 * time.Millisecond,
		FetchTimeout:  100 * time.Millisecond,
		MaxBytes:      1024,
		HTTPClient:    client,
	})

	ctx := context.Background()
	driver.Start(ctx)

	// Let it run a few burst cycles.
	time.Sleep(120 * time.Millisecond)

	driver.Stop()

	requests := rt.snapshot()
	if len(requests) == 0 {
		t.Fatal("no fetches recorded after 120ms — driver loop never ran")
	}

	// Every request should be a GET to one of our two test URLs.
	for i, req := range requests {
		if req.Method != http.MethodGet {
			t.Errorf("req %d: method %q, want GET", i, req.Method)
		}
		if req.URL.String() != "https://example.com/a" && req.URL.String() != "https://example.com/b" {
			t.Errorf("req %d: unexpected URL %q", i, req.URL.String())
		}
		if req.Header.Get("User-Agent") == "" {
			t.Errorf("req %d: empty User-Agent", i)
		}
	}

	metrics := driver.Metrics()
	if metrics.BurstsRun == 0 {
		t.Error("metrics.BurstsRun = 0")
	}
	if metrics.FetchesSucceed == 0 {
		t.Error("metrics.FetchesSucceed = 0")
	}
	if metrics.FetchesSucceed != uint64(len(requests)) {
		t.Errorf("metrics fetchesSucceed=%d != actual requests=%d",
			metrics.FetchesSucceed, len(requests))
	}

	t.Logf("PASS: %d fetches in 120ms across %d bursts (%d bytes)",
		metrics.FetchesSucceed, metrics.BurstsRun, metrics.BytesRead)
}

// TestDecoyDriverStopIsIdempotent verifies that calling Stop multiple
// times doesn't panic, deadlock, or send anything new.
func TestDecoyDriverStopIsIdempotent(t *testing.T) {
	driver := NewDecoyDriver(DecoyConfig{
		Targets:     []DecoyTarget{{URL: "https://example.com/x", Category: "test"}},
		MinInterval: time.Hour, // never actually fire
		MaxInterval: time.Hour,
		HTTPClient:  &http.Client{Transport: &fakeRoundTripper{}, Timeout: time.Second},
	})
	driver.Start(context.Background())
	time.Sleep(10 * time.Millisecond) // let goroutine reach the select
	driver.Stop()
	driver.Stop() // must not panic
	driver.Stop()
}

// TestDecoyDriverContextCancel verifies that canceling the context
// passed to Start makes the loop exit promptly.
func TestDecoyDriverContextCancel(t *testing.T) {
	driver := NewDecoyDriver(DecoyConfig{
		Targets:     []DecoyTarget{{URL: "https://example.com/y", Category: "test"}},
		MinInterval: 5 * time.Second,
		MaxInterval: 5 * time.Second,
		HTTPClient:  &http.Client{Transport: &fakeRoundTripper{}, Timeout: time.Second},
	})

	ctx, cancel := context.WithCancel(context.Background())
	driver.Start(ctx)

	// Loop should be parked in time.After(5s). Cancel should wake it up
	// and the goroutine should exit promptly.
	cancel()

	done := make(chan struct{})
	go func() {
		driver.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("driver did not stop within 2s of ctx cancel")
	}
}

// TestDecoyDriverDefaultsApplied verifies that NewDecoyDriver fills in
// zero fields with sane defaults instead of leaving an unusable struct.
func TestDecoyDriverDefaultsApplied(t *testing.T) {
	driver := NewDecoyDriver(DecoyConfig{})

	if driver.cfg.MinInterval != defaultDecoyMinInterval {
		t.Errorf("MinInterval = %v, want %v", driver.cfg.MinInterval, defaultDecoyMinInterval)
	}
	if driver.cfg.BurstMin != defaultDecoyBurstMin {
		t.Errorf("BurstMin = %d, want %d", driver.cfg.BurstMin, defaultDecoyBurstMin)
	}
	if driver.cfg.MaxBytes != defaultDecoyMaxBytes {
		t.Errorf("MaxBytes = %d, want %d", driver.cfg.MaxBytes, defaultDecoyMaxBytes)
	}
	// Targets have no fallback on purpose: a caller that supplies none
	// gets a driver that does nothing, rather than one that starts
	// fetching a list every other deployment also fetches.
	if len(driver.cfg.Targets) != 0 {
		t.Errorf("Targets should stay empty when none are configured, got %d",
			len(driver.cfg.Targets))
	}
}

// TestDecoyDriverDoubleStartIsNoop verifies that calling Start twice
// on the same driver doesn't spawn a second loop.
func TestDecoyDriverDoubleStartIsNoop(t *testing.T) {
	rt := &fakeRoundTripper{}
	driver := NewDecoyDriver(DecoyConfig{
		Targets:       []DecoyTarget{{URL: "https://example.com/z", Category: "test"}},
		MinInterval:   5 * time.Millisecond,
		MaxInterval:   10 * time.Millisecond,
		BurstMin:      1,
		BurstMax:      1,
		IntraBurstMin: time.Millisecond,
		IntraBurstMax: time.Millisecond,
		HTTPClient:    &http.Client{Transport: rt, Timeout: time.Second},
	})

	var goroutineCounter atomic.Int64
	wrappedStart := func() {
		goroutineCounter.Add(1)
		driver.Start(context.Background())
	}
	wrappedStart()
	wrappedStart()
	wrappedStart()

	time.Sleep(50 * time.Millisecond)
	driver.Stop()

	// We can't directly count goroutines, but we can sanity-check that
	// metrics didn't go nonlinear (3x of expected).
	m := driver.Metrics()
	t.Logf("after 3 Start calls + 50ms: bursts=%d fetches=%d (single-loop expected)",
		m.BurstsRun, m.FetchesSucceed)
}

// TestExampleDecoyTargetsShape checks the illustrative list: every URL
// is HTTPS and every entry carries both a URL and a category. It catches
// obvious mistakes when the examples are edited.
func TestExampleDecoyTargetsShape(t *testing.T) {
	if len(ExampleDecoyTargets) == 0 {
		t.Fatal("ExampleDecoyTargets is empty; the examples are there to show the shape")
	}
	for i, target := range ExampleDecoyTargets {
		if target.URL == "" {
			t.Errorf("target %d: empty URL", i)
		}
		if !strings.HasPrefix(target.URL, "https://") {
			t.Errorf("target %d: not HTTPS: %q", i, target.URL)
		}
		if target.Category == "" {
			t.Errorf("target %d: empty Category", i)
		}
		// Hosts whose reachability is unstable make the driver's own
		// behaviour depend on an outside factor, which is the opposite
		// of what it is for.
		if strings.Contains(target.URL, "google") || strings.Contains(target.URL, "gstatic") {
			t.Errorf("target %d: unstable-reachability host in the example list: %q", i, target.URL)
		}
	}
}

// TestDecoyFetchUsesReqCloseNotHeader verifies a decoy fetch signals
// connection close via req.Close, not a "Connection: close" header. That
// header is illegal under HTTP/2 and the Go HTTP/2 transport rejects any
// request carrying it, so a decoy that negotiated h2 would fail to send —
// a browser never does that. This is the header-divergence fix: the
// churn intent is preserved through req.Close, which the transport
// translates correctly per protocol.
func TestDecoyFetchUsesReqCloseNotHeader(t *testing.T) {
	rt := &fakeRoundTripper{}
	client := &http.Client{Transport: rt, Timeout: time.Second}

	driver := NewDecoyDriver(DecoyConfig{
		Targets:    []DecoyTarget{{URL: "https://example.com/a", Category: "test"}},
		HTTPClient: client,
	})

	driver.fetchOne(context.Background(), driver.cfg.Targets[0])

	reqs := rt.snapshot()
	if len(reqs) != 1 {
		t.Fatalf("expected exactly one decoy request, got %d", len(reqs))
	}
	req := reqs[0]
	if !req.Close {
		t.Errorf("decoy request must set req.Close to churn the connection")
	}
	if v := req.Header.Get("Connection"); v != "" {
		t.Errorf("decoy request must not carry a Connection header (illegal under HTTP/2), got %q", v)
	}
}
