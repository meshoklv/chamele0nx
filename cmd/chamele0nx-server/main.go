// chamele0nx-server runs the Chamele0nX Transport server — a VPN tunnel
// disguised as a real HTTPS service via TLS record shaping.
//
// Usage:
//
//	chamele0nx-server -cert /path/to/cert.pem -key /path/to/key.pem -secret <hex>
//
// The server serves a cover website to unauthenticated visitors and tunnels
// VPN data for authenticated clients through the same HTTPS connection.
// TLS record sizes are shaped to match a real site's traffic profile.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meshoklv/chamele0nx/transport/chamele0nx"
)

func main() {
	addr := flag.String("addr", ":443", "Listen address (host:port)")
	cert := flag.String("cert", "", "TLS certificate path (PEM)")
	key := flag.String("key", "", "TLS private key path (PEM)")
	apiPath := flag.String("api-path", "/api/v1/events", "Tunnel API endpoint")
	serverID := flag.String("server-id", "chamele0nx-1", "Server identifier")
	secret := flag.String("secret", "", "User secret (hex-encoded, 32+ bytes). If empty, generates and prints one.")
	secretFile := flag.String("secret-file", "", "Read the hex-encoded user secret from this file instead of -secret (preferred: keeps the secret out of the process arguments)")
	cookieFmt := flag.String("cookie-format", "generic", "Auth cookie format: generic, wordpress, django")
	coverDir := flag.String("cover-dir", "", "Directory to serve as cover website (optional)")
	profilePath := flag.String("profile", "", "Site profile JSON for TLS record shaping (optional, uses built-in server-downstream profile)")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute, "Idle timeout for relayed streams (close streams with no activity)")
	logFormat := flag.String("log-format", "json", "Log format: text or json")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	// Kill-switch: bypass server-side TLS record shaping on a hot
	// re-deploy if throughput regresses. See the documentation on
	// ServerConfig.DisableDownstreamShaping for the full rationale.
	// Accepts either the flag or the environment variable
	// CHAMELE0NX_DISABLE_DOWNSTREAM_SHAPING=1, so the switch can be
	// flipped in a hurry without editing the service unit file.
	disableDownstreamShaping := flag.Bool("disable-downstream-shaping", false,
		"Disable server-side TLS record shaping (kill-switch; weakens ML-DPI resistance — operator escape hatch only)")
	flag.Parse()
	exitIfVersionRequested("chamele0nx-server")

	setupLogging(*logFormat, *logLevel)

	if *cert == "" || *key == "" {
		fmt.Fprintf(os.Stderr, "Usage: chamele0nx-server -cert CERT -key KEY [-secret HEX]\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Resolve the user secret, most specific source first:
	//   -secret-file  → -secret  → $CHAMELE0NX_SECRET_FILE
	//   → $CHAMELE0NX_SECRET → generate a fresh one and print it.
	//
	// The file-based sources exist because anything passed as a command
	// line argument is readable by every user on the box via `ps`.
	var userSecret []byte
	secretHex, err := resolveSecret(*secretFile, *secret)
	if err != nil {
		slog.Error("read secret", "error", err)
		os.Exit(1)
	}
	if secretHex == "" {
		// Generate a random secret and print it.
		userSecret = make([]byte, 32)
		if _, err := rand.Read(userSecret); err != nil {
			slog.Error("generate secret", "error", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Generated user secret (save this for client config):\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", hex.EncodeToString(userSecret))
	} else {
		userSecret, err = hex.DecodeString(secretHex)
		if err != nil {
			slog.Error("decode secret", "error", err)
			os.Exit(1)
		}
		if len(userSecret) < 16 {
			slog.Error("secret too short", "len", len(userSecret))
			os.Exit(1)
		}
	}

	// Load optional profile.
	var profile *chamele0nx.SiteProfile
	if *profilePath != "" {
		p, err := chamele0nx.LoadProfile(*profilePath)
		if err != nil {
			slog.Error("load profile", "error", err)
			os.Exit(1)
		}
		profile = p
		slog.Info("loaded traffic profile", "name", p.Name)
	}

	// Environment variable fallback: flag takes precedence, then env, then default
	// (false → shape downstream). Accept the common "truthy" spellings so
	// the operator doesn't have to remember which one the harness parses.
	disableShape := *disableDownstreamShaping
	if !disableShape {
		switch os.Getenv("CHAMELE0NX_DISABLE_DOWNSTREAM_SHAPING") {
		case "1", "true", "TRUE", "yes", "YES", "on", "ON":
			disableShape = true
		}
	}

	srv := chamele0nx.NewServer(chamele0nx.ServerConfig{
		ListenAddr:               *addr,
		TLSCert:                  *cert,
		TLSKey:                   *key,
		APIPath:                  *apiPath,
		ServerID:                 *serverID,
		UserSecrets:              map[string][]byte{*serverID: userSecret},
		CookieFormat:             *cookieFmt,
		CoverSiteDir:             *coverDir,
		Profile:                  profile,
		IdleTimeout:              *idleTimeout,
		Logger:                   slog.Default(),
		DisableDownstreamShaping: disableShape,
	})

	slog.Info("starting chamele0nx server",
		"addr", *addr,
		"api_path", *apiPath,
		"server_id", *serverID,
		"cover_dir", *coverDir,
		"downstream_shaping", !disableShape,
	)

	// Run TLS server in a goroutine so signal handler can call Shutdown.
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.ListenAndServeTLS()
	}()

	// Wait for either server error or shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case err := <-serverErr:
			if err != nil {
				slog.Error("server stopped", "error", err)
				os.Exit(1)
			}
			return
		case sig := <-sigCh:
			slog.Info("received shutdown signal, draining active tunnels", "signal", sig)
			// Give in-flight tunnels 30s to finish, then force-close.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				slog.Warn("graceful drain timed out, force-closed remaining connections", "error", err)
			} else {
				slog.Info("clean shutdown")
			}
			// Wait briefly for ListenAndServeTLS to return after the
			// listener closes. The channel is buffered so a missed drain
			// here doesn't leak goroutines.
			drainWait := time.After(2 * time.Second)
			select {
			case <-serverErr:
			case <-drainWait:
			}
			return
		}
	}
}

// setupLogging configures slog with the requested format and level.
// Server logs operational metrics only — no client IPs, secrets, or cookies.
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
