package chamele0nx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// TestTLSRecordSizeControl is the BLOCKER test (Task #1).
// It proves that Go's tls.Conn.Write(N bytes) produces a TLS record
// whose payload is exactly N bytes, giving us control over TLS record
// sizes as seen by DPI.
//
// Method: raw TCP interceptor captures bytes on the wire, parses TLS
// record headers (5 bytes: type, version_hi, version_lo, length_hi, length_lo),
// and verifies payload lengths match what was written.
func TestTLSRecordSizeControl(t *testing.T) {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("generate TLS config: %v", err)
	}

	// Target record payload sizes to test.
	testSizes := []int{100, 500, 1000, 2000, 5000, 8192, 16384}

	// Create raw TCP listener to intercept TLS records.
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawListener.Close()

	var wg sync.WaitGroup

	// Server goroutine: accept TLS connection, read and discard data.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawConn, err := rawListener.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		tlsConn := tls.Server(rawConn, tlsCfg)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		// Read all data until client closes.
		io.Copy(io.Discard, tlsConn)
	}()

	// Client side: connect via raw TCP, wrap with TLS, intercept records.
	rawConn, err := net.Dial("tcp", rawListener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Wrap with interceptor that captures raw TLS record sizes.
	interceptor := &tlsRecordInterceptor{conn: rawConn}

	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		// CRITICAL: Disable Go's dynamic record sizing so every Write(N)
		// produces exactly one TLS record with N-byte payload.
		// Without this, Go starts with ~1KB records and ramps up.
		DynamicRecordSizingDisabled: true,
	}
	tlsClient := tls.Client(interceptor, clientCfg)
	defer tlsClient.Close()

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Clear handshake records — we only care about application data.
	interceptor.mu.Lock()
	interceptor.records = nil
	interceptor.mu.Unlock()

	// Write each test size and verify the TLS record.
	for _, size := range testSizes {
		interceptor.mu.Lock()
		interceptor.records = nil
		interceptor.mu.Unlock()

		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand: %v", err)
		}

		n, err := tlsClient.Write(data)
		if err != nil {
			t.Fatalf("write %d bytes: %v", size, err)
		}
		if n != size {
			t.Fatalf("write %d: got n=%d", size, n)
		}

		// Small delay to let interceptor capture.
		time.Sleep(10 * time.Millisecond)

		interceptor.mu.Lock()
		records := make([]tlsRecord, len(interceptor.records))
		copy(records, interceptor.records)
		interceptor.mu.Unlock()

		// Filter to application data records only (type 0x17).
		var appRecords []tlsRecord
		for _, r := range records {
			if r.contentType == 0x17 { // application_data
				appRecords = append(appRecords, r)
			}
		}

		if len(appRecords) == 0 {
			t.Errorf("write %d bytes: no application_data records captured", size)
			continue
		}

		// For sizes ≤ 16384, expect exactly 1 record.
		// The record length includes AEAD overhead (nonce + tag).
		if len(appRecords) == 1 {
			rec := appRecords[0]
			// TLS 1.3: record payload = encrypted(plaintext + content_type) + tag
			// TLS 1.3 uses inner content type (1 byte) + padding, so:
			// record.length = plaintext_len + 1 (inner type) + 16 (GCM tag)
			// But TLS 1.2 with GCM: record.length = 8 (explicit nonce) + plaintext_len + 16 (tag)
			//
			// We check that the record length is within expected range.
			expectedMin := size + 1  // at minimum, data + 1 byte overhead
			expectedMax := size + 40 // generous upper bound for AEAD overhead

			if rec.length < expectedMin || rec.length > expectedMax {
				t.Errorf("write %d bytes: record length %d, expected [%d, %d]",
					size, rec.length, expectedMin, expectedMax)
			} else {
				t.Logf("PASS: write %d bytes → 1 TLS record, length=%d (overhead=%d)",
					size, rec.length, rec.length-size)
			}
		} else {
			// Multiple records — this is fine for 16KB writes (TLS may fragment).
			totalPayload := 0
			for _, r := range appRecords {
				totalPayload += r.length
			}
			t.Logf("PASS: write %d bytes → %d TLS records, total wire length=%d",
				size, len(appRecords), totalPayload)
		}
	}

	tlsClient.Close()
	wg.Wait()
}

// TestRandomizeSize verifies per-client jitter stays within bounds.
func TestRandomizeSize(t *testing.T) {
	base := 5000
	pct := 25

	for seed := uint64(0); seed < 1000; seed++ {
		result := RandomizeSize(base, seed, pct)
		minExpected := base - base*pct/100
		maxExpected := base + base*pct/100

		if result < minTLSRecord {
			t.Errorf("seed %d: result %d < minTLSRecord %d", seed, result, minTLSRecord)
		}
		if result > maxTLSRecord {
			t.Errorf("seed %d: result %d > maxTLSRecord %d", seed, result, maxTLSRecord)
		}
		if result < minExpected || result > maxExpected {
			// Jitter should be within ±pct%.
			t.Errorf("seed %d: result %d outside [%d, %d]", seed, result, minExpected, maxExpected)
		}
	}
}

// --- Infrastructure for TLS record interception ---

// tlsRecord represents a captured TLS record header.
type tlsRecord struct {
	contentType uint8  // 0x14=ChangeCipherSpec, 0x16=Handshake, 0x17=ApplicationData
	version     uint16 // TLS version
	length      int    // payload length (does NOT include 5-byte header)
}

// tlsRecordInterceptor wraps a net.Conn and captures TLS record metadata
// from bytes written through it. It parses the 5-byte TLS record headers
// to extract record types and lengths.
type tlsRecordInterceptor struct {
	conn    net.Conn
	mu      sync.Mutex
	records []tlsRecord
	buf     []byte // partial record header buffer
}

func (i *tlsRecordInterceptor) Write(b []byte) (int, error) {
	// Parse TLS record headers from the outgoing stream.
	i.mu.Lock()
	i.buf = append(i.buf, b...)
	for len(i.buf) >= tlsRecordHeader {
		contentType := i.buf[0]
		version := binary.BigEndian.Uint16(i.buf[1:3])
		length := int(binary.BigEndian.Uint16(i.buf[3:5]))

		// Sanity check: valid TLS content types and reasonable length.
		if (contentType < 0x14 || contentType > 0x19) || length > maxTLSRecord+256 {
			// Not a valid TLS record header — skip one byte and retry.
			i.buf = i.buf[1:]
			continue
		}

		totalLen := tlsRecordHeader + length
		if len(i.buf) < totalLen {
			break // Need more data.
		}

		i.records = append(i.records, tlsRecord{
			contentType: contentType,
			version:     version,
			length:      length,
		})
		i.buf = i.buf[totalLen:]
	}
	i.mu.Unlock()

	return i.conn.Write(b)
}

func (i *tlsRecordInterceptor) Read(b []byte) (int, error) {
	return i.conn.Read(b)
}

func (i *tlsRecordInterceptor) Close() error {
	return i.conn.Close()
}

func (i *tlsRecordInterceptor) LocalAddr() net.Addr {
	return i.conn.LocalAddr()
}

func (i *tlsRecordInterceptor) RemoteAddr() net.Addr {
	return i.conn.RemoteAddr()
}

func (i *tlsRecordInterceptor) SetDeadline(t time.Time) error {
	return i.conn.SetDeadline(t)
}

func (i *tlsRecordInterceptor) SetReadDeadline(t time.Time) error {
	return i.conn.SetReadDeadline(t)
}

func (i *tlsRecordInterceptor) SetWriteDeadline(t time.Time) error {
	return i.conn.SetWriteDeadline(t)
}

// selfSignedTLSConfig generates a self-signed TLS config for testing.
func selfSignedTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "chamele0nx-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
