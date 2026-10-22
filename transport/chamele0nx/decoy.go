package chamele0nx

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// DecoyDriver runs background TLS connections to popular CDN/analytics
// domains in parallel with the real Chamele0nX tunnel, breaking the
// "this device only ever talks to one IP" flow signature.
//
// Without DecoyDriver, the only TLS connection a Chamele0nX-
// using device makes is to vpn.example.com. Real Chrome browsing the same
// SaaS dashboard concurrently fans out to fonts.bunny.net, cdnjs,
// jsdelivr, sentry, plausible, etc. DecoyDriver makes those calls FROM
// the user's device (NOT through the tunnel) so the device's outbound
// TLS pattern looks like a normal browsing session, not a single
// long-lived tunnel.
//
// IMPORTANT — VPN routing trap. On Android / iOS, when the user has the
// Chamele0nX VpnService / PacketTunnelProvider active, by default ALL
// outbound traffic (including DecoyDriver fetches) is routed THROUGH
// the tunnel. That defeats the entire purpose: instead of a fan of
// independent TLS connections to many IPs, we end up with N more
// requests stuffed into the same one tunnel.
//
// To get the intended effect, the native VPN client code MUST exclude
// DecoyDriver's sockets from the tunnel:
//
//   - Android: call VpnService.protect(socket.fd) before connecting,
//     OR list each decoy domain in addDisallowedApplication / equivalent
//   - iOS: configure includedRoutes / excludedRoutes on the
//     PacketTunnelProvider so decoy IPs route via cellular, not utun
//
// Without that integration this driver is a no-op for stealth purposes.
// It will still run and emit metrics, so you can wire it up first and
// add the protect() call from the native client side later.
//
// Lifecycle:
//
//	d := NewDecoyDriver(DecoyConfig{Logger: ...})
//	d.Start(ctx)            // returns immediately, runs in background
//	defer d.Stop()
//
// Stop is idempotent and safe to call after Start has returned an error.

// DecoyConfig tunes a DecoyDriver. All fields are optional — zero
// values resolve to sensible defaults via the const block below.
type DecoyConfig struct {
	// Targets is the list of decoy URLs to fetch. There is no default:
	// with none supplied the driver runs and fetches nothing. See
	// ExampleDecoyTargets for the shape of a useful entry.
	Targets []DecoyTarget

	// MinInterval / MaxInterval bound the random gap between decoy bursts.
	// Default 30s / 10min.
	MinInterval time.Duration
	MaxInterval time.Duration

	// BurstMin / BurstMax bound the random number of fetches per burst.
	// Default 3 / 6.
	BurstMin int
	BurstMax int

	// IntraBurstMin / IntraBurstMax bound the random gap between
	// individual fetches within one burst (matches real page-load fan-out
	// where assets request 200ms-3s apart). Default 200ms / 3s.
	IntraBurstMin time.Duration
	IntraBurstMax time.Duration

	// FetchTimeout is the per-request timeout. Default 5s.
	FetchTimeout time.Duration

	// MaxBytes is the cap on response bytes read per fetch. Default 4096.
	MaxBytes int64

	// HTTPClient lets the caller inject a custom client (used by tests
	// to swap the network layer). Default: http.Client built with a
	// stdlib transport.
	//
	// **Production builds should inject a uTLS-backed client** matching
	// the real Chamele0nX tunnel TLS fingerprint. Without it the decoy
	// fetches go out with Go's own crypto/tls ClientHello (its own
	// JA3/JA4), so a device running the tunnel presents two different TLS
	// fingerprints from one address — the tunnel's Chrome hello and the
	// decoy's Go hello — while every request claims to be Chrome. A
	// correlating observer can tie the two together.
	//
	// This is not wired here because a faithful uTLS client for
	// arbitrary third-party hosts is a larger piece than a header tweak:
	// it needs a RoundTripper that runs a uTLS Chrome handshake, keeps
	// the real Chrome ALPN (both h2 and http/1.1) and therefore speaks
	// whichever the host negotiates, and does standard per-host
	// certificate verification — none of which the tunnel's h2-only,
	// pinned dialer provides directly. Until that lands, inject a client
	// here in production; the header-level divergence
	// ("Connection: close" under HTTP/2) that used to break these
	// fetches is already fixed in fetchOne.
	HTTPClient *http.Client

	// Logger for structured logging. Default slog.Default.
	Logger *slog.Logger
}

// DecoyTarget is one URL the decoy driver may fetch.
type DecoyTarget struct {
	URL      string // exact URL, e.g. "https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css"
	Category string // for logging only ("cdn", "fonts", "package")
}

// Defaults applied when DecoyConfig leaves a field zero.
const (
	defaultDecoyMinInterval   = 30 * time.Second
	defaultDecoyMaxInterval   = 10 * time.Minute
	defaultDecoyBurstMin      = 3
	defaultDecoyBurstMax      = 6
	defaultDecoyIntraBurstMin = 200 * time.Millisecond
	defaultDecoyIntraBurstMax = 3 * time.Second
	defaultDecoyFetchTimeout  = 5 * time.Second
	defaultDecoyMaxBytes      = 4096
)

// ExampleDecoyTargets is an illustrative list, not a default. It shows
// the shape of a useful target: reachable, small in response, and the
// kind of endpoint a developer's machine contacts continuously anyway.
//
// It is deliberately short, and the driver does not fall back to it.
// Two reasons. The first is the same one that keeps traffic profiles out
// of this repository: a list every deployment shares is a list every
// deployment can be recognised by. The second is that these are other
// people's services, which have not agreed to receive automated
// background traffic; polling someone else's API from thousands of
// devices to no purpose is an abuse of it regardless of what it costs
// them. Choose hosts you operate, or hosts whose terms permit this.
//
// Privacy note worth passing on to whoever ships a client: these
// requests leave the user's device outside the tunnel, on purpose, so
// each named service observes the device's real network address, just
// as an ordinary browser visiting it would. This project neither
// receives nor stores anything about that, but a user should be told it
// happens before the driver is switched on.
var ExampleDecoyTargets = []DecoyTarget{
	{URL: "https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css", Category: "cdn"},
	{URL: "https://fonts.bunny.net/css?family=inter:400", Category: "fonts"},
	{URL: "https://api.github.com/zen", Category: "dev-infra"},
	{URL: "https://en.wikipedia.org/wiki/Special:Random", Category: "reference"},
	{URL: "https://www.cloudflare.com/cdn-cgi/trace", Category: "cdn"},
}

// DecoyDriver is the running instance.
type DecoyDriver struct {
	cfg    DecoyConfig
	client *http.Client
	logger *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool

	// metrics — atomic counters for ops visibility
	burstsRun      atomic.Uint64
	fetchesRun     atomic.Uint64
	fetchesSucceed atomic.Uint64
	fetchesFail    atomic.Uint64
	bytesRead      atomic.Uint64
}

// NewDecoyDriver constructs a driver but does NOT start it. Call Start
// to begin background fetches.
func NewDecoyDriver(cfg DecoyConfig) *DecoyDriver {
	if cfg.MinInterval <= 0 {
		cfg.MinInterval = defaultDecoyMinInterval
	}
	if cfg.MaxInterval <= 0 {
		cfg.MaxInterval = defaultDecoyMaxInterval
	}
	if cfg.MinInterval > cfg.MaxInterval {
		cfg.MinInterval, cfg.MaxInterval = cfg.MaxInterval, cfg.MinInterval
	}
	if cfg.BurstMin <= 0 {
		cfg.BurstMin = defaultDecoyBurstMin
	}
	if cfg.BurstMax <= 0 {
		cfg.BurstMax = defaultDecoyBurstMax
	}
	if cfg.BurstMin > cfg.BurstMax {
		cfg.BurstMin, cfg.BurstMax = cfg.BurstMax, cfg.BurstMin
	}
	if cfg.IntraBurstMin <= 0 {
		cfg.IntraBurstMin = defaultDecoyIntraBurstMin
	}
	if cfg.IntraBurstMax <= 0 {
		cfg.IntraBurstMax = defaultDecoyIntraBurstMax
	}
	if cfg.IntraBurstMin > cfg.IntraBurstMax {
		cfg.IntraBurstMin, cfg.IntraBurstMax = cfg.IntraBurstMax, cfg.IntraBurstMin
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = defaultDecoyFetchTimeout
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultDecoyMaxBytes
	}
	// No fallback list on purpose: see ExampleDecoyTargets. A driver
	// with no targets starts and does nothing, which is the safe
	// outcome for a caller that forgot to configure it.

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.FetchTimeout}
	}

	return &DecoyDriver{
		cfg:    cfg,
		client: client,
		logger: logger,
	}
}

// Start launches the background loop. Returns immediately. Pass a
// context that you cancel to stop the driver, or call Stop().
//
// Calling Start more than once is a no-op (subsequent calls return).
func (d *DecoyDriver) Start(ctx context.Context) {
	if d.closed.Load() {
		return
	}
	if d.cancel != nil {
		return // already started
	}
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.wg.Add(1)
	go d.run(ctx)
}

// Stop signals the background loop to exit and waits for it. Idempotent.
func (d *DecoyDriver) Stop() {
	if !d.closed.CompareAndSwap(false, true) {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

// Metrics returns a snapshot of operational counters. Safe to call from
// any goroutine.
func (d *DecoyDriver) Metrics() DecoyMetrics {
	return DecoyMetrics{
		BurstsRun:      d.burstsRun.Load(),
		FetchesRun:     d.fetchesRun.Load(),
		FetchesSucceed: d.fetchesSucceed.Load(),
		FetchesFail:    d.fetchesFail.Load(),
		BytesRead:      d.bytesRead.Load(),
	}
}

// DecoyMetrics is a point-in-time snapshot of driver counters.
type DecoyMetrics struct {
	BurstsRun      uint64
	FetchesRun     uint64
	FetchesSucceed uint64
	FetchesFail    uint64
	BytesRead      uint64
}

// run is the main loop: wait random interval → run a burst → repeat.
func (d *DecoyDriver) run(ctx context.Context) {
	defer d.wg.Done()
	d.logger.Info("decoy driver started",
		"targets", len(d.cfg.Targets),
		"burst_range", fmt.Sprintf("%d-%d", d.cfg.BurstMin, d.cfg.BurstMax),
		"interval_range", fmt.Sprintf("%v-%v", d.cfg.MinInterval, d.cfg.MaxInterval),
	)
	defer d.logger.Info("decoy driver stopped",
		"bursts", d.burstsRun.Load(),
		"fetches", d.fetchesRun.Load(),
		"bytes", d.bytesRead.Load(),
	)

	for {
		// Wait random interval before next burst.
		wait := randomDuration(d.cfg.MinInterval, d.cfg.MaxInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		d.runBurst(ctx)
	}
}

// runBurst fetches a random subset of targets at random intra-burst
// intervals. Records metrics, logs at debug level.
func (d *DecoyDriver) runBurst(ctx context.Context) {
	burstSize := randomInt(d.cfg.BurstMin, d.cfg.BurstMax)
	d.burstsRun.Add(1)
	d.logger.Debug("decoy burst start", "size", burstSize)

	for i := 0; i < burstSize; i++ {
		// Random delay before this fetch (skip for the first one in burst).
		if i > 0 {
			gap := randomDuration(d.cfg.IntraBurstMin, d.cfg.IntraBurstMax)
			select {
			case <-ctx.Done():
				return
			case <-time.After(gap):
			}
		}

		target := d.cfg.Targets[randomInt(0, len(d.cfg.Targets)-1)]
		d.fetchOne(ctx, target)
	}
}

// fetchOne does a single decoy GET. The body is read up to MaxBytes
// then dropped. Errors are logged but never propagated — decoy
// failures are operationally OK (a CDN being slow doesn't break the
// real tunnel).
func (d *DecoyDriver) fetchOne(ctx context.Context, target DecoyTarget) {
	d.fetchesRun.Add(1)

	// Use a fresh per-request UA from the pool, picked by a fresh
	// random seed so the decoy traffic isn't correlated to any single
	// user identity. This is intentional — we WANT decoy fetches to
	// look like a normal device, not like one specific Chamele0nX user.
	var seedBuf [8]byte
	_, _ = rand.Read(seedBuf[:])
	ua := pickUserAgent(binary.LittleEndian.Uint64(seedBuf[:]))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		d.fetchesFail.Add(1)
		d.logger.Debug("decoy build request failed", "url", target.URL, "error", err)
		return
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	// Don't keep TCP alive across decoys — the connection churn should
	// look like a browser fanning out to several sites. Set this through
	// req.Close, not a "Connection: close" header: that header is illegal
	// under HTTP/2 (per RFC 7540) and the Go HTTP/2 transport rejects
	// any request carrying it, so a decoy that negotiated h2 would fail
	// to send at all — a browser never does that. req.Close expresses the
	// same intent and the transport translates it correctly per protocol.
	req.Close = true

	resp, err := d.client.Do(req)
	if err != nil {
		d.fetchesFail.Add(1)
		d.logger.Debug("decoy fetch failed", "url", target.URL, "error", err)
		return
	}
	// The body is read and discarded below; a close failure cannot change
	// the byte counters this fetch reports.
	defer func() { _ = resp.Body.Close() }()

	// Read up to MaxBytes then drop.
	limited := io.LimitReader(resp.Body, d.cfg.MaxBytes)
	n, _ := io.Copy(io.Discard, limited)
	d.bytesRead.Add(uint64(n))
	d.fetchesSucceed.Add(1)

	d.logger.Debug("decoy fetch ok",
		"category", target.Category,
		"status", resp.StatusCode,
		"bytes", n,
	)
}

// randomDuration returns a uniform random duration in [min, max].
// Uses crypto/rand because we don't want predictable timing patterns.
func randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	span := int64(max - min)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return min
	}
	return min + time.Duration(n.Int64())
}

// randomInt returns a uniform random int in [min, max] (inclusive).
func randomInt(min, max int) int {
	if min >= max {
		return min
	}
	span := int64(max - min + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}
