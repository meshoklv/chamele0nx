package chamele0nx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/meshoklv/chamele0nx/transport"

	"golang.org/x/net/http2"
)

// TestPersistentClientReconnect verifies that when the underlying tunnel
// dies (we forcibly close it from outside), the PersistentClient detects
// death via the done channel and brings up a new tunnel automatically.
// After reconnect, a SOCKS5 request through the stable listener still works.
func TestPersistentClientReconnect(t *testing.T) {
	// 1. Echo target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	echoAddr := echoLn.Addr().String()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	// 2. Chamele0nX test server.
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	userSecret := make([]byte, 32)
	if _, err := rand.Read(userSecret); err != nil {
		t.Fatal(err)
	}
	serverID := "persistent-test-server"
	apiPath := "/api/v1/events"

	srv := NewServer(ServerConfig{
		APIPath:             apiPath,
		CookieFormat:        "generic",
		UserSecrets:         map[string][]byte{serverID: userSecret},
		ServerID:            serverID,
		AllowPrivateTargets: true,
		Logger:              slog.Default(),
	})

	serverTLSCfg := &tls.Config{
		Certificates:                tlsCfg.Certificates,
		NextProtos:                  []string{"h2"},
		DynamicRecordSizingDisabled: true,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	h2s := &http2.Server{}
	serverHandler := srv.Handler()
	serverProfile := DefaultSaaSProfile()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						c.Close()
						return
					}
				}
				shaped := NewShapedConn(c, serverProfile, generateClientSeed())
				h2s.ServeConn(shaped, &http2.ServeConnOpts{Handler: serverHandler})
			}(conn)
		}
	}()
	serverAddr := ln.Addr().String()

	// 3. Build a Transport with stdlib TLS dialer (no uTLS — self-signed cert).
	transportInst := newTestTransport(tlsCfg)

	endpoint := transport.Endpoint{
		ID:        serverID,
		Address:   serverAddr,
		Transport: "chamele0nx",
		Params: map[string]string{
			"chameleon_addr":   serverAddr,
			"chameleon_sni":    "localhost",
			"chameleon_path":   apiPath,
			"chameleon_cookie": "generic",
			"user_secret":      hex.EncodeToString(userSecret),
			"server_id":        serverID,
		},
	}

	// 4. Start PersistentClient on a random port.
	pc := NewPersistentClient(transportInst, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := pc.Start(ctx, 0); err != nil {
		t.Fatalf("persistent start: %v", err)
	}
	defer pc.Close()

	socksAddr := pc.SocksAddr()
	t.Logf("PersistentClient SOCKS5 at %s", socksAddr)

	// 5. Wait for first tunnel to come up (max 5s).
	firstTun := waitForTunnelInTest(t, pc, 5*time.Second)
	if firstTun == nil {
		t.Fatal("first tunnel never established")
	}
	attempts1, ok1 := pc.Stats()
	t.Logf("first tunnel up; stats: attempts=%d ok=%d", attempts1, ok1)
	if ok1 != 1 {
		t.Errorf("expected 1 successful connect, got %d", ok1)
	}

	// 6. Verify SOCKS5 works on first tunnel.
	if err := smokeSOCKS5(socksAddr, echoHost, echoPort, "first"); err != nil {
		t.Fatalf("smoke test 1: %v", err)
	}

	// 7. Forcibly kill the current tunnel (simulates network drop).
	t.Log("force-killing current tunnel to trigger reconnect")
	firstTun.Close()

	// 8. Wait for new tunnel to replace it.
	deadline := time.Now().Add(10 * time.Second)
	var secondTun *Tunnel
	for time.Now().Before(deadline) {
		t2 := pc.current.Load()
		if t2 != nil && t2 != firstTun && !t2.IsClosed() {
			secondTun = t2
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if secondTun == nil {
		t.Fatal("PersistentClient did not establish a new tunnel after force-close")
	}
	attempts2, ok2 := pc.Stats()
	t.Logf("second tunnel up; stats: attempts=%d ok=%d", attempts2, ok2)
	if ok2 < 2 {
		t.Errorf("expected ≥2 successful connects after reconnect, got %d", ok2)
	}

	// 9. Verify SOCKS5 still works on the SAME stable address but routed
	// through the new tunnel.
	if err := smokeSOCKS5(socksAddr, echoHost, echoPort, "second"); err != nil {
		t.Fatalf("smoke test 2: %v", err)
	}
	t.Log("PASS: SOCKS5 stable across tunnel reconnect")
}

// TestPersistentClientCloseStops verifies Close stops the reconnect loop
// and the accept loop without leaks.
func TestPersistentClientCloseStops(t *testing.T) {
	// Use an endpoint that points to a closed port — connect will always
	// fail, so the reconnect loop will just spin in backoff.
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	transportInst := newTestTransport(tlsCfg)

	endpoint := transport.Endpoint{
		ID:        "dead-server",
		Address:   "127.0.0.1:1", // port 1 will refuse connection
		Transport: "chamele0nx",
		Params: map[string]string{
			"chameleon_addr":   "127.0.0.1:1",
			"chameleon_sni":    "localhost",
			"chameleon_path":   "/api/v1/events",
			"chameleon_cookie": "generic",
			"user_secret":      "00000000000000000000000000000000",
			"server_id":        "dead-server",
		},
	}

	pc := NewPersistentClient(transportInst, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pc.Start(ctx, 0); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Let reconnect loop attempt at least one connect (which will fail).
	time.Sleep(200 * time.Millisecond)

	closeStart := time.Now()
	if err := pc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	closeDur := time.Since(closeStart)

	// Close should return promptly (waitgroup wait should be fast since
	// reconnect loop respects ctx.Done()).
	if closeDur > 3*time.Second {
		t.Errorf("Close took too long: %v (expected < 3s)", closeDur)
	}
	t.Logf("Close returned in %v", closeDur)

	attempts, ok := pc.Stats()
	t.Logf("stats: attempts=%d ok=%d", attempts, ok)
	if ok != 0 {
		t.Errorf("expected 0 successful connects to dead endpoint, got %d", ok)
	}

	// Second close is no-op.
	if err := pc.Close(); err != nil {
		t.Errorf("second close returned error: %v", err)
	}
}

// TestPersistentClientFatalEndpoint verifies that fatal config errors
// (missing required params) stop the reconnect loop instead of looping forever.
func TestPersistentClientFatalEndpoint(t *testing.T) {
	transportInst := New()

	// Missing user_secret → validateChamele0nXParams returns fatal error.
	endpoint := transport.Endpoint{
		ID:        "broken",
		Address:   "127.0.0.1:1",
		Transport: "chamele0nx",
		Params: map[string]string{
			"chameleon_addr": "127.0.0.1:1",
			// no user_secret
		},
	}

	pc := NewPersistentClient(transportInst, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pc.Start(ctx, 0); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer pc.Close()

	// Reconnect loop should attempt once, see fatal, and exit. We give it
	// up to 1 second to do that.
	time.Sleep(1 * time.Second)

	attempts, ok := pc.Stats()
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt for fatal config, got %d", attempts)
	}
	if ok != 0 {
		t.Errorf("expected 0 successes, got %d", ok)
	}
}

// TestPersistentClientGracefulShutdown verifies that Shutdown waits for
// active SOCKS5 handlers to drain (or until ctx expires) and that new
// connections accepted during drain get dropped cleanly.
func TestPersistentClientGracefulShutdown(t *testing.T) {
	// 1. Slow echo target — sleeps before echoing so we can hold a stream
	// open while Shutdown is called.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				// Hold the connection open for 500ms to simulate a long
				// in-flight request, then echo back.
				time.Sleep(500 * time.Millisecond)
				if n > 0 {
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()
	echoAddr := echoLn.Addr().String()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	// 2. Chamele0nX test server.
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	userSecret := make([]byte, 32)
	if _, err := rand.Read(userSecret); err != nil {
		t.Fatal(err)
	}
	serverID := "shutdown-test-server"
	apiPath := "/api/v1/events"

	srv := NewServer(ServerConfig{
		APIPath:             apiPath,
		CookieFormat:        "generic",
		UserSecrets:         map[string][]byte{serverID: userSecret},
		ServerID:            serverID,
		AllowPrivateTargets: true,
		Logger:              slog.Default(),
	})

	serverTLSCfg := &tls.Config{
		Certificates:                tlsCfg.Certificates,
		NextProtos:                  []string{"h2"},
		DynamicRecordSizingDisabled: true,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	h2s := &http2.Server{}
	serverHandler := srv.Handler()
	serverProfile := DefaultSaaSProfile()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						c.Close()
						return
					}
				}
				shaped := NewShapedConn(c, serverProfile, generateClientSeed())
				h2s.ServeConn(shaped, &http2.ServeConnOpts{Handler: serverHandler})
			}(conn)
		}
	}()
	serverAddr := ln.Addr().String()

	// 3. PersistentClient.
	transportInst := newTestTransport(tlsCfg)
	endpoint := transport.Endpoint{
		ID:        serverID,
		Address:   serverAddr,
		Transport: "chamele0nx",
		Params: map[string]string{
			"chameleon_addr":   serverAddr,
			"chameleon_sni":    "localhost",
			"chameleon_path":   apiPath,
			"chameleon_cookie": "generic",
			"user_secret":      hex.EncodeToString(userSecret),
			"server_id":        serverID,
		},
	}
	pc := NewPersistentClient(transportInst, endpoint)
	if err := pc.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}

	if waitForTunnelInTest(t, pc, 5*time.Second) == nil {
		t.Fatal("first tunnel never came up")
	}
	socksAddr := pc.SocksAddr()

	// 4. Start a long-running SOCKS5 connection in the background that
	// will be in-flight when we call Shutdown. The slow echo above means
	// it takes ~500ms to complete; Shutdown with 2s deadline should drain
	// it cleanly.
	connDone := make(chan error, 1)
	go func() {
		conn, err := dialSOCKS5(socksAddr, echoHost, echoPort)
		if err != nil {
			connDone <- fmt.Errorf("dial: %w", err)
			return
		}
		defer conn.Close()
		payload := []byte("graceful")
		if _, err := conn.Write(payload); err != nil {
			connDone <- fmt.Errorf("write: %w", err)
			return
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			connDone <- fmt.Errorf("read: %w", err)
			return
		}
		if !bytes.Equal(buf, payload) {
			connDone <- fmt.Errorf("echo mismatch: %q vs %q", buf, payload)
			return
		}
		connDone <- nil
	}()

	// Give the goroutine a moment to actually start the SOCKS5 negotiation
	// and reach the slow echo server (so it's in flight when Shutdown fires).
	time.Sleep(150 * time.Millisecond)

	// 5. Call Shutdown with 2-second deadline. Should drain the in-flight
	// connection cleanly.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	shutdownStart := time.Now()
	err = pc.Shutdown(shutdownCtx)
	shutdownDur := time.Since(shutdownStart)
	t.Logf("Shutdown returned in %v (err=%v)", shutdownDur, err)

	if err != nil {
		t.Errorf("Shutdown unexpectedly returned error: %v", err)
	}

	// 6. The in-flight connection should have completed successfully.
	select {
	case connErr := <-connDone:
		if connErr != nil {
			t.Errorf("in-flight connection failed during graceful drain: %v", connErr)
		} else {
			t.Log("PASS: in-flight connection drained cleanly during Shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Error("in-flight connection never completed")
	}

	// 7. After Shutdown, the listener must be closed (new connect fails fast).
	_, err = net.DialTimeout("tcp", socksAddr, 200*time.Millisecond)
	if err == nil {
		t.Error("expected listener to be closed after Shutdown, dial succeeded")
	}
}

// TestPersistentClientShutdownTimeout verifies that Shutdown returns
// ctx.Err() when active connections don't drain within the deadline.
func TestPersistentClientShutdownTimeout(t *testing.T) {
	// Black-hole echo target: accept connection, never read or echo.
	// This makes our SOCKS5 handler block forever in the relay loop.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			// Hold open, never read.
			go func(c net.Conn) {
				time.Sleep(5 * time.Second)
				c.Close()
			}(conn)
		}
	}()
	echoAddr := echoLn.Addr().String()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	// Chamele0nX server (same shape as previous test, factored later).
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	userSecret := make([]byte, 32)
	rand.Read(userSecret)
	serverID := "timeout-test"
	srv := NewServer(ServerConfig{
		APIPath:             "/api/v1/events",
		CookieFormat:        "generic",
		UserSecrets:         map[string][]byte{serverID: userSecret},
		ServerID:            serverID,
		AllowPrivateTargets: true,
		Logger:              slog.Default(),
	})
	serverTLSCfg := &tls.Config{
		Certificates:                tlsCfg.Certificates,
		NextProtos:                  []string{"h2"},
		DynamicRecordSizingDisabled: true,
	}
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	defer ln.Close()
	h2s := &http2.Server{}
	handler := srv.Handler()
	profile := DefaultSaaSProfile()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						c.Close()
						return
					}
				}
				shaped := NewShapedConn(c, profile, generateClientSeed())
				h2s.ServeConn(shaped, &http2.ServeConnOpts{Handler: handler})
			}(conn)
		}
	}()

	pc := NewPersistentClient(newTestTransport(tlsCfg), transport.Endpoint{
		ID:      serverID,
		Address: ln.Addr().String(),
		Params: map[string]string{
			"chameleon_addr":   ln.Addr().String(),
			"chameleon_sni":    "localhost",
			"chameleon_path":   "/api/v1/events",
			"chameleon_cookie": "generic",
			"user_secret":      hex.EncodeToString(userSecret),
			"server_id":        serverID,
		},
	})
	if err := pc.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if waitForTunnelInTest(t, pc, 5*time.Second) == nil {
		t.Fatal("tunnel never came up")
	}
	socksAddr := pc.SocksAddr()

	// Open a SOCKS5 connection that will block forever (target accepts but
	// never reads or echoes).
	go func() {
		conn, err := dialSOCKS5(socksAddr, echoHost, echoPort)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hangs"))
		// Try to read — will block forever (or until force close).
		buf := make([]byte, 1)
		conn.Read(buf)
	}()

	time.Sleep(150 * time.Millisecond) // let the connection get into the relay loop

	// Shutdown with very short deadline → drain will time out, force close.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = pc.Shutdown(shutdownCtx)
	if err == nil {
		t.Error("expected Shutdown to return ctx deadline error, got nil")
	} else {
		t.Logf("PASS: Shutdown timed out as expected: %v", err)
	}
}

// TestServerIdleTimeout verifies that a stream with no data flow gets
// torn down on the server side after IdleTimeout.
func TestServerIdleTimeout(t *testing.T) {
	// 1. Slow target: accept conn, hold open without sending. The stream
	// will be entirely idle from the target side.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			// Hold without ever reading or sending.
			go func(c net.Conn) {
				time.Sleep(10 * time.Second)
				c.Close()
			}(conn)
		}
	}()
	echoAddr := echoLn.Addr().String()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	// 2. Server with very short idle timeout (300ms) to make the test fast.
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	userSecret := make([]byte, 32)
	rand.Read(userSecret)
	serverID := "idle-test"

	srv := NewServer(ServerConfig{
		APIPath:             "/api/v1/events",
		CookieFormat:        "generic",
		UserSecrets:         map[string][]byte{serverID: userSecret},
		ServerID:            serverID,
		AllowPrivateTargets: true,
		Logger:              slog.Default(),
		IdleTimeout:         300 * time.Millisecond,
	})

	serverTLSCfg := &tls.Config{
		Certificates:                tlsCfg.Certificates,
		NextProtos:                  []string{"h2"},
		DynamicRecordSizingDisabled: true,
	}
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	defer ln.Close()
	h2s := &http2.Server{}
	handler := srv.Handler()
	profile := DefaultSaaSProfile()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						c.Close()
						return
					}
				}
				shaped := NewShapedConn(c, profile, generateClientSeed())
				h2s.ServeConn(shaped, &http2.ServeConnOpts{Handler: handler})
			}(conn)
		}
	}()

	pc := NewPersistentClient(newTestTransport(tlsCfg), transport.Endpoint{
		ID:      serverID,
		Address: ln.Addr().String(),
		Params: map[string]string{
			"chameleon_addr":   ln.Addr().String(),
			"chameleon_sni":    "localhost",
			"chameleon_path":   "/api/v1/events",
			"chameleon_cookie": "generic",
			"user_secret":      hex.EncodeToString(userSecret),
			"server_id":        serverID,
		},
	})
	if err := pc.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if waitForTunnelInTest(t, pc, 5*time.Second) == nil {
		t.Fatal("tunnel never came up")
	}
	socksAddr := pc.SocksAddr()

	// 3. Open a SOCKS5 connection to the slow target. The connection
	// will be idle (no data either way), so server-side IdleTimeout
	// should fire after 300ms and tear down the stream.
	conn, err := dialSOCKS5(socksAddr, echoHost, echoPort)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Try to read from the connection — should fail within ~1 second
	// because the server-side timeout closed the stream.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	start := time.Now()
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	if n > 0 {
		t.Errorf("expected no data, got %d bytes", n)
	}
	if err == nil {
		t.Error("expected error after idle timeout, got nil")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("idle timeout took too long: %v (expected < 1.5s for 300ms timeout)", elapsed)
	}
	t.Logf("idle stream closed after %v (err=%v)", elapsed, err)
}

// TestClassifyConnectErr verifies the classifier puts errors in the right
// bucket. The classifier is substring-based so test what we actually emit.
func TestClassifyConnectErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want errClass
	}{
		{"nil", nil, errClassNetwork},
		{"fatal-config", fmt.Errorf("invalid chamele0nx endpoint: missing required param: chameleon_addr"), errClassFatal},
		{"fatal-missing-param", fmt.Errorf("missing required param: user_secret"), errClassFatal},
		{"auth-server-401", fmt.Errorf("server returned 401"), errClassAuth},
		{"auth-server-403", fmt.Errorf("server returned 403"), errClassAuth},
		{"auth-bad-keyx", fmt.Errorf("invalid server key exchange frame"), errClassAuth},
		{"auth-read-fail", fmt.Errorf("read server pubkey: unexpected EOF"), errClassAuth},
		{"network-tcp", fmt.Errorf("h2 post: dial tcp 1.2.3.4:443: connection refused"), errClassNetwork},
		{"network-tls", fmt.Errorf("h2 post: utls handshake: remote error: tls: handshake failure"), errClassNetwork},
		{"network-h2", fmt.Errorf("h2 post: stream error: stream ID 1; PROTOCOL_ERROR"), errClassNetwork},
		{"network-timeout", fmt.Errorf("h2 post: context deadline exceeded"), errClassNetwork},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyConnectErr(c.err)
			if got != c.want {
				t.Errorf("classifyConnectErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestNextBackoff verifies the backoff function caps correctly.
func TestNextBackoff(t *testing.T) {
	cases := []struct {
		current time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{1 * time.Second, 60 * time.Second, 2 * time.Second},
		{2 * time.Second, 60 * time.Second, 4 * time.Second},
		{30 * time.Second, 60 * time.Second, 60 * time.Second},
		{60 * time.Second, 60 * time.Second, 60 * time.Second},
		{120 * time.Second, 60 * time.Second, 60 * time.Second},
	}
	for _, c := range cases {
		got := nextBackoff(c.current, c.max)
		if got != c.want {
			t.Errorf("nextBackoff(%v, %v) = %v, want %v", c.current, c.max, got, c.want)
		}
	}
}

// TestJitterBackoff verifies jitter factor stays in [0.5, 1.5) so N clients
// that all hit the same retry point after a shared disruption cannot end up
// reconnecting in lockstep.
func TestJitterBackoff(t *testing.T) {
	// d == 0 is a no-op to avoid zero-duration edge cases around startup.
	if got := jitterBackoff(0); got != 0 {
		t.Errorf("jitterBackoff(0) = %v, want 0", got)
	}

	const base = 10 * time.Second
	const minExpected = base / 2     // 5s
	const maxExpected = 3 * base / 2 // 15s
	const iterations = 2000

	var (
		seenBelow bool
		seenAbove bool
	)
	for i := 0; i < iterations; i++ {
		got := jitterBackoff(base)
		if got < minExpected {
			t.Fatalf("jitterBackoff(%v)=%v below min %v", base, got, minExpected)
		}
		if got >= maxExpected {
			t.Fatalf("jitterBackoff(%v)=%v >= max %v", base, got, maxExpected)
		}
		// Spread sanity: over 2000 samples we must see values on both sides
		// of the base — otherwise jitter is degenerate (constant or one-sided).
		if got < base {
			seenBelow = true
		}
		if got > base {
			seenAbove = true
		}
	}
	if !seenBelow || !seenAbove {
		t.Errorf("jitterBackoff distribution one-sided: seenBelow=%v seenAbove=%v", seenBelow, seenAbove)
	}
}

// --- helpers ---

// newTestTransport creates a Transport that dials self-signed test servers
// using the stdlib TLS dialer (skipping uTLS Chrome fingerprinting).
func newTestTransport(tlsCfg *tls.Config) *Transport {
	t := New()
	t.tlsDialFn = func(ctx context.Context, addr, sni string) (net.Conn, error) {
		dialer := &tls.Dialer{
			Config: &tls.Config{
				InsecureSkipVerify:          true,
				ServerName:                  sni,
				NextProtos:                  []string{"h2"},
				DynamicRecordSizingDisabled: true,
			},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		// Force handshake so http2 sees a ready conn.
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	return t
}

// waitForTunnelInTest polls until current tunnel is non-nil or timeout.
func waitForTunnelInTest(t *testing.T, pc *PersistentClient, timeout time.Duration) *Tunnel {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tun := pc.current.Load(); tun != nil && !tun.IsClosed() {
			return tun
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// smokeSOCKS5 opens a SOCKS5 connection through proxyAddr to the given target,
// echoes a tag, and verifies the round-trip.
func smokeSOCKS5(proxyAddr, host string, port int, tag string) error {
	conn, err := dialSOCKS5(proxyAddr, host, port)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	payload := []byte("hello-" + tag)
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if !bytes.Equal(buf, payload) {
		return fmt.Errorf("echo mismatch: got %q, want %q", buf, payload)
	}
	return nil
}
