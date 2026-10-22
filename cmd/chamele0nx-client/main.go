// chamele0nx-client connects to a Chamele0nX Transport server and opens
// a stable local SOCKS5 proxy with automatic reconnection on tunnel loss.
//
// Usage:
//
//	chamele0nx-client -server vpn.example.com:443 -secret <hex>
//
// Then configure your browser/app to use SOCKS5 proxy at 127.0.0.1:<port>.
//
// The SOCKS5 listener stays bound on the same port for the entire lifetime
// of the process. The underlying VPN tunnel is re-established automatically
// on network errors with exponential backoff (1s → 60s).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meshoklv/chamele0nx/transport"
	"github.com/meshoklv/chamele0nx/transport/chamele0nx"
)

func main() {
	os.Exit(run())
}

// run holds the whole client lifecycle and returns the process exit code.
// Keeping os.Exit out of it means the deferred cancels and shutdown paths
// below are guaranteed to run.
func run() int {
	server := flag.String("server", "", "Server address (host:port, e.g., vpn.example.com:443)")
	sni := flag.String("sni", "", "TLS SNI (defaults to host from -server)")
	secret := flag.String("secret", "", "User secret (hex-encoded)")
	secretFile := flag.String("secret-file", "", "Read the hex-encoded user secret from this file instead of -secret")
	serverID := flag.String("server-id", "chamele0nx-1", "Server identifier")
	apiPath := flag.String("api-path", "/api/v1/events", "Tunnel API endpoint")
	cookieFmt := flag.String("cookie-format", "generic", "Cookie format: generic, wordpress, django")
	profilePath := flag.String("profile", "", "Site profile JSON (optional)")
	socksPort := flag.Int("port", 0, "Local SOCKS5 port (0 = random)")
	check := flag.Bool("check", false, "Connect, check external IP via tunnel, then exit")
	checkTimeout := flag.Duration("check-timeout", 30*time.Second, "Timeout for -check mode (must include reconnect grace)")
	logFormat := flag.String("log-format", "text", "Log format: text or json")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")

	// Optional cover profile selection. An empty string resolves to
	// chamele0nx.DefaultCoverID ("saas-http2") at connect time, so the
	// flag can be ignored entirely unless extra covers are compiled in.
	cover := flag.String("cover", "", "Cover profile ID (empty = saas-http2)")

	flag.Parse()
	exitIfVersionRequested("chamele0nx-client")

	setupLogging(*logFormat, *logLevel)

	if *server == "" {
		fmt.Fprintf(os.Stderr, "Usage: chamele0nx-client -server HOST:PORT -secret HEX\n\n")
		flag.PrintDefaults()
		return 1
	}

	secretHex, err := resolveSecret(*secretFile, *secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read secret: %v\n", err)
		return 1
	}
	if secretHex == "" {
		slog.Error("secret required: use -secret flag or CHAMELE0NX_SECRET env var")
		return 1
	}

	ct := chamele0nx.New()

	// user_secret is passed as hex; chamele0nx.Transport decodes it. The
	// CLI used to pre-decode and stuff raw bytes into the params map as a
	// Go string, which worked in-process but broke any path that round-
	// trips the endpoint through JSON (mobile/, invite blobs).
	params := map[string]string{
		"chameleon_addr":   *server,
		"chameleon_path":   *apiPath,
		"chameleon_cookie": *cookieFmt,
		"user_secret":      secretHex,
		"server_id":        *serverID,
	}
	if *sni != "" {
		params["chameleon_sni"] = *sni
	}
	if *profilePath != "" {
		params["chameleon_profile"] = *profilePath
	}

	// Cover profile selection. An empty -cover keeps the default
	// (saas-http2). A cover that needs its own rendezvous parameters
	// reads them from the same params map; the transport validates the
	// name up front so an unknown cover fails before we touch the
	// network.
	if *cover != "" {
		params["cover"] = *cover
	}

	endpoint := transport.Endpoint{
		ID:        *serverID,
		Address:   *server,
		Transport: "chamele0nx",
		Params:    params,
	}

	// The server address is deliberately not logged at this level. A
	// client log often ends up on disk under a supervisor, and the one
	// field in it that matters to anyone reading it later is where the
	// user was connecting.
	slog.Info("connecting to chamele0nx server")
	slog.Debug("chamele0nx server address", "server", *server)

	// PersistentClient owns the SOCKS5 listener and re-establishes the
	// underlying tunnel on failure. Lifetime tied to the root context
	// cancelled by SIGINT/SIGTERM.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	pc := chamele0nx.NewPersistentClient(ct, endpoint)
	if err := pc.Start(rootCtx, *socksPort); err != nil {
		slog.Error("start persistent client", "error", err)
		return 1
	}

	socksAddr := pc.SocksAddr()

	if *check {
		// In check mode we wait for the first tunnel to come up and then
		// fetch the external IP. Bounded by checkTimeout.
		checkCtx, cancel := context.WithTimeout(rootCtx, *checkTimeout)
		defer cancel()
		if !waitForTunnelReady(checkCtx, pc) {
			slog.Error("tunnel did not come up within check-timeout", "timeout", *checkTimeout)
			// PersistentClient.Close is idempotent and never reports a
			// failure; the exit code already says what went wrong.
			_ = pc.Close()
			return 1
		}
		slog.Info("tunnel established", "socks5", socksAddr)
		if err := checkIP(socksAddr); err != nil {
			slog.Error("check IP failed", "error", err)
			_ = pc.Close()
			return 1
		}
		// Use immediate Close in -check: nothing to drain.
		_ = pc.Close()
		return 0
	}

	slog.Info("SOCKS5 listener ready (stable across reconnects)", "socks5", socksAddr)
	fmt.Printf("\nSOCKS5 proxy ready at %s\n", socksAddr)
	fmt.Printf("Test: curl --socks5-hostname %s https://ifconfig.me\n\n", socksAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down (graceful, draining active connections)...")
	// Give in-flight SOCKS5 connections 10s to finish before force-closing
	// the tunnel. After 10s anything still running gets dropped.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := pc.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful drain timed out, force-closed remaining connections", "error", err)
	} else {
		slog.Info("clean shutdown")
	}
	rootCancel()
	return 0
}

// waitForTunnelReady polls the persistent client's stats until at least
// one successful connect has been recorded, or ctx expires.
func waitForTunnelReady(ctx context.Context, pc *chamele0nx.PersistentClient) bool {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, ok := pc.Stats()
		if ok > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// setupLogging configures slog with the requested format and level.
// We never log PII (client IPs, secrets, cookies); all log fields are
// either operational metrics or remote endpoints.
func setupLogging(format, level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}

	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default:
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// checkIP fetches the external IP through the SOCKS5 tunnel to verify
// connectivity, printing it on success.
func checkIP(socksAddr string) error {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://%s", socksAddr))
	if err != nil {
		return fmt.Errorf("parse socks5 proxy url: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}

	resp, err := client.Get("https://ifconfig.me/ip")
	if err != nil {
		return err
	}
	// Nothing actionable can come of a failed close on a response we have
	// already finished reading.
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	fmt.Printf("External IP through tunnel: %s\n", string(body))
	return nil
}
