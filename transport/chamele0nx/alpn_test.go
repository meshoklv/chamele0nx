package chamele0nx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedPEM generates a self-signed cert for localhost and
// writes cert.pem / key.pem into dir, returning their paths. Needed
// because ListenAndServeTLS loads the keypair from files.
func writeSelfSignedPEM(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "chamele0nx-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestServerALPNServesHTTP11AndH2 verifies the server offers and serves
// both h2 and http/1.1. Advertising only h2 is a one-handshake
// discriminator: a real site answers an http/1.1 handshake, an h2-only
// server sends no_application_protocol. The server must now answer an
// http/1.1 handshake with the cover site, while h2 still works. On both
// protocols the API path answers 401 to an unauthenticated caller.
func TestServerALPNServesHTTP11AndH2(t *testing.T) {
	certPath, keyPath := writeSelfSignedPEM(t, t.TempDir())

	port, err := findFreePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv := NewServer(ServerConfig{
		ListenAddr:   addr,
		TLSCert:      certPath,
		TLSKey:       keyPath,
		APIPath:      "/api/v1/events",
		CookieFormat: "generic",
		UserSecrets:  map[string][]byte{"srv1": []byte("secret")},
		ServerID:     "srv1",
		Logger:       slog.Default(),
	})
	go func() { _ = srv.ListenAndServeTLS() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	get := func(alpn []string, forceH2 bool, path string) (*http.Response, error) {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: alpn},
			ForceAttemptHTTP2: forceH2,
			DisableKeepAlives: true,
		}
		c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		return c.Get(fmt.Sprintf("https://%s%s", addr, path))
	}

	// Wait for the listener to come up (ListenAndServeTLS runs async).
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := get([]string{"http/1.1"}, false, "/api/v1/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// HTTP/1.1: cover site is served (not a protocol refusal).
	resp, err := get([]string{"http/1.1"}, false, "/api/v1/health")
	if err != nil {
		t.Fatalf("http/1.1 GET health: %v", err)
	}
	if resp.ProtoMajor != 1 {
		t.Errorf("expected HTTP/1.x, negotiated %s", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("http/1.1 health: want 200, got %d", resp.StatusCode)
	}
	_ = body

	// HTTP/1.1: API path answers 401 to an anonymous caller.
	resp, err = get([]string{"http/1.1"}, false, "/api/v1/events")
	if err != nil {
		t.Fatalf("http/1.1 GET events: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("http/1.1 events: want 401, got %d", resp.StatusCode)
	}

	// h2 still works: cover site over HTTP/2.
	resp, err = get([]string{"h2"}, true, "/api/v1/health")
	if err != nil {
		t.Fatalf("h2 GET health: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("expected HTTP/2, negotiated %s", resp.Proto)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("h2 health: want 200, got %d", resp.StatusCode)
	}
}
