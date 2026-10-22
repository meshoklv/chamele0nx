package chamele0nx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/meshoklv/chamele0nx/transport"

	stdhttp2 "golang.org/x/net/http2"
)

// ---------------------------------------------------------------------------
// Unit tests: RFC 1928 §7 UDP header encode/parse.
// ---------------------------------------------------------------------------

func TestUDPHeaderEncodeParseRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		host string
		port int
	}{
		{"ipv4", "1.1.1.1", 53},
		{"ipv4-high-port", "8.8.4.4", 65535},
		{"domain", "example.com", 443},
	}
	payload := []byte("the quick brown fox jumps over 0x00\xff\x01")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dg := encodeUDPDatagram(c.host, c.port, payload)
			host, port, addrPortRaw, gotPayload, err := parseUDPHeader(dg)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if port != c.port {
				t.Errorf("port: got %d want %d", port, c.port)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Errorf("payload mismatch: got %q want %q", gotPayload, payload)
			}
			// The domain form round-trips the literal host; the IPv4 form
			// round-trips the canonical dotted-quad.
			if c.name == "domain" {
				if host != c.host {
					t.Errorf("host: got %q want %q", host, c.host)
				}
			} else {
				if net.ParseIP(host) == nil || net.ParseIP(host).String() != net.ParseIP(c.host).String() {
					t.Errorf("host: got %q want %q", host, c.host)
				}
			}
			// addrPortRaw must rebuild an identical reply datagram.
			rebuilt := buildUDPDatagram(addrPortRaw, payload)
			if !bytes.Equal(rebuilt, dg) {
				t.Errorf("rebuild mismatch:\n got %x\nwant %x", rebuilt, dg)
			}
		})
	}
}

func TestUDPHeaderRejectsIPv6(t *testing.T) {
	// RSV RSV FRAG ATYP=0x04 + 16 addr bytes + 2 port bytes + data.
	dg := []byte{0x00, 0x00, 0x00, 0x04}
	dg = append(dg, make([]byte, 16)...)  // IPv6 addr
	dg = append(dg, 0x01, 0xbb)           // port 443
	dg = append(dg, []byte("payload")...) // data
	if _, _, _, _, err := parseUDPHeader(dg); !errors.Is(err, errUDPIPv6Blocked) {
		t.Fatalf("expected errUDPIPv6Blocked, got %v", err)
	}
}

func TestUDPHeaderRejectsFragment(t *testing.T) {
	dg := encodeUDPDatagram("1.1.1.1", 53, []byte("x"))
	dg[2] = 0x01 // FRAG != 0
	if _, _, _, _, err := parseUDPHeader(dg); !errors.Is(err, errUDPFragUnsupported) {
		t.Fatalf("expected errUDPFragUnsupported, got %v", err)
	}
}

func TestUDPHeaderRejectsShort(t *testing.T) {
	if _, _, _, _, err := parseUDPHeader([]byte{0x00, 0x00}); !errors.Is(err, errUDPShortHeader) {
		t.Fatalf("expected errUDPShortHeader, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration harness: server transport + client transport wired in-memory,
// mirroring TestEndToEndTunnel. Returns the client tunnel and a cleanup.
// ---------------------------------------------------------------------------

func newUDPIntegrationTunnel(t *testing.T) *Tunnel {
	t.Helper()

	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	userSecret := make([]byte, 32)
	if _, err := rand.Read(userSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	serverID := "udp-test-server"
	apiPath := "/api/v1/events"

	srv := NewServer(ServerConfig{
		APIPath:             apiPath,
		CookieFormat:        "generic",
		UserSecrets:         map[string][]byte{serverID: userSecret},
		ServerID:            serverID,
		AllowPrivateTargets: true, // test-only: UDP echo is on loopback
		Logger:              slog.Default(),
	})

	serverTLSCfg := &tls.Config{
		Certificates:                tlsCfg.Certificates,
		NextProtos:                  []string{"h2"},
		DynamicRecordSizingDisabled: true,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	h2s := &stdhttp2.Server{}
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
				h2s.ServeConn(shaped, &stdhttp2.ServeConnOpts{Handler: serverHandler})
			}(conn)
		}
	}()

	serverAddr := ln.Addr().String()

	tun, err := connectChamele0nXTest(context.Background(), New(), transport.Endpoint{
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
	}, tlsCfg.Certificates[0])
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { tun.Close() })

	return tun.(*Tunnel)
}

// socks5UDPAssociate performs the SOCKS5 UDP ASSOCIATE control handshake and
// returns the relay UDP address plus the control TCP conn (kept open by the
// caller for the association lifetime).
func socks5UDPAssociate(t *testing.T, proxyAddr string) (*net.UDPAddr, net.Conn) {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("bad auth reply: %x", resp)
	}
	// UDP ASSOCIATE, ATYP IPv4, DST 0.0.0.0:0 (RFC lets the client omit it).
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate req: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("associate failed: status %d", reply[1])
	}
	ip := net.IPv4(reply[4], reply[5], reply[6], reply[7])
	port := int(reply[8])<<8 | int(reply[9])
	return &net.UDPAddr{IP: ip, Port: port}, ctrl
}

// startUDPEcho starts a loopback UDP echo server and returns its address.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], src)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// TestUDPAssociateEchoRoundTrip drives a real UDP datagram round-trip through
// the whole mux path: client SOCKS5 UDP ASSOCIATE → mux stream → server UDP
// dial → loopback echo → back. Local-echo for determinism (no egress needed).
func TestUDPAssociateEchoRoundTrip(t *testing.T) {
	echoAddr := startUDPEcho(t)
	tun := newUDPIntegrationTunnel(t)

	relayAddr, ctrl := socks5UDPAssociate(t, tun.SocksAddr())
	defer ctrl.Close()

	uc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer uc.Close()

	payload := []byte("quic-hello-\x00\x01\x02through-the-tunnel")
	dg := encodeUDPDatagram("127.0.0.1", echoAddr.Port, payload)
	if _, err := uc.Write(dg); err != nil {
		t.Fatalf("write datagram: %v", err)
	}

	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	rbuf := make([]byte, 64*1024)
	n, err := uc.Read(rbuf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	_, port, _, gotPayload, err := parseUDPHeader(rbuf[:n])
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if port != echoAddr.Port {
		t.Errorf("reply dst port: got %d want %d", port, echoAddr.Port)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", gotPayload, payload)
	}
	t.Logf("PASS: %d-byte datagram round-tripped through the encrypted mux", len(payload))
}

// TestUDPAssociateBoundaryPreserved verifies two datagrams in yield two
// datagrams out — boundaries are preserved, not coalesced into one read.
func TestUDPAssociateBoundaryPreserved(t *testing.T) {
	echoAddr := startUDPEcho(t)
	tun := newUDPIntegrationTunnel(t)

	relayAddr, ctrl := socks5UDPAssociate(t, tun.SocksAddr())
	defer ctrl.Close()

	uc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer uc.Close()

	p1 := []byte("first-datagram")
	p2 := []byte("second-and-longer-datagram-payload")
	for _, p := range [][]byte{p1, p2} {
		if _, err := uc.Write(encodeUDPDatagram("127.0.0.1", echoAddr.Port, p)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	got := map[string]bool{}
	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 2; i++ {
		rbuf := make([]byte, 64*1024)
		n, err := uc.Read(rbuf) // one Read == one datagram (never coalesced)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		_, _, _, payload, err := parseUDPHeader(rbuf[:n])
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		got[string(payload)] = true
	}
	if !got[string(p1)] || !got[string(p2)] {
		t.Fatalf("boundary/coalesce failure: got set %v, want both %q and %q", got, p1, p2)
	}
	t.Logf("PASS: two datagrams in, two distinct datagrams out (no coalescing)")
}

// TestUDPAssociateRealDNS optionally drives a real DNS query for example.com
// to 1.1.1.1:53 through the tunnel. Skipped if egress is unavailable so the
// suite stays deterministic; the local-echo tests above are the required path.
func TestUDPAssociateRealDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network DNS test in -short mode")
	}
	tun := newUDPIntegrationTunnel(t)
	relayAddr, ctrl := socks5UDPAssociate(t, tun.SocksAddr())
	defer ctrl.Close()

	uc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer uc.Close()

	// Minimal DNS query: A record for example.com, ID 0x1234, RD set.
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := uc.Write(encodeUDPDatagram("1.1.1.1", 53, query)); err != nil {
		t.Fatalf("write dns: %v", err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(4 * time.Second))
	rbuf := make([]byte, 64*1024)
	n, err := uc.Read(rbuf)
	if err != nil {
		t.Skipf("no DNS response (egress likely unavailable): %v", err)
	}
	_, _, _, resp, err := parseUDPHeader(rbuf[:n])
	if err != nil {
		t.Fatalf("parse dns reply: %v", err)
	}
	if len(resp) < 12 || resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("bad DNS response header: % x", resp[:min(12, len(resp))])
	}
	// QR bit set + at least one answer.
	if resp[2]&0x80 == 0 {
		t.Fatalf("DNS QR bit not set")
	}
	t.Logf("PASS: real DNS A-query for example.com resolved through the tunnel (%d-byte answer)", len(resp))
}
