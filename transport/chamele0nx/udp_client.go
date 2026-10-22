package chamele0nx

// udp_client.go — client-side SOCKS5 UDP ASSOCIATE support.
//
// WHY THIS EXISTS. hev-socks5-tunnel (the iOS/desktop packet tunnel) relays
// UDP by opening a SOCKS5 UDP ASSOCIATE and shipping each datagram, wrapped in
// an RFC 1928 §7 UDP header, to the relay socket the proxy hands back. Until
// this file landed, the Chamele0nX client rejected CMD != CONNECT, so all UDP
// (crucially QUIC — YouTube/Google on iOS) silently died and apps had to fall
// back to TCP. This makes UDP work end-to-end WITHOUT any new wire: every
// datagram rides the existing encrypted HTTP/2 mux stream via Stream.Write-
// Datagram / ReadDatagram. No new port, no plaintext UDP on the wire.
//
// SHAPE. handleUDPAssociate binds a loopback UDP relay socket, replies with
// its port, then keeps the control TCP conn open as the association lifetime.
// Each distinct (client-src, dst) pair is a "flow": the first datagram opens a
// mux UDP stream to the server; a per-flow goroutine reads datagrams back off
// that stream and writes them to the client with the SOCKS5 UDP header rebuilt.
// When the control conn closes, the relay socket + all flow streams tear down.

import (
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// RFC 1928 §7 UDP header parse errors.
var (
	errUDPShortHeader     = errUDP("udp header too short")
	errUDPFragUnsupported = errUDP("udp fragmentation (FRAG!=0) not supported")
	errUDPTruncated       = errUDP("udp header truncated")
	errUDPIPv6Blocked     = errUDP("udp IPv6 target (ATYP=0x04) blocked")
	errUDPBadATYP         = errUDP("udp unknown ATYP")
)

// errUDP is a tiny string-error type so the parse errors are comparable and
// carry a clear "chamele0nx:" prefix without pulling in fmt on this path.
type errUDP string

func (e errUDP) Error() string { return "chamele0nx: " + string(e) }

// maxUDPFlows caps concurrent UDP flows per association, bounding memory and FD
// use if a client sprays datagrams at many destinations.
const maxUDPFlows = 256

// udpRelayBufSize is the read buffer for the loopback relay socket. 64 KiB is
// the max UDP payload; QUIC/DNS datagrams are far smaller.
const udpRelayBufSize = 64 * 1024

// parseUDPHeader parses an RFC 1928 §7 SOCKS5 UDP request header:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//
// It returns the destination host/port, the raw ATYP+ADDR+PORT slice (reused
// verbatim to build reply headers), and the DATA payload. FRAG != 0 and
// ATYP == IPv6 (0x04) are rejected — Chamele0nX does not fragment, and it
// blocks IPv6 targets because the tunnel carries IPv4 only; letting an
// IPv6 target through would leak the flow outside the tunnel.
func parseUDPHeader(p []byte) (host string, port int, addrPortRaw []byte, payload []byte, err error) {
	if len(p) < 4 {
		return "", 0, nil, nil, errUDPShortHeader
	}
	// p[0], p[1] = RSV (ignored); p[2] = FRAG; p[3] = ATYP.
	if p[2] != 0x00 {
		return "", 0, nil, nil, errUDPFragUnsupported
	}
	atyp := p[3]
	var hdrEnd int
	switch atyp {
	case 0x01: // IPv4
		if len(p) < 4+4+2 {
			return "", 0, nil, nil, errUDPTruncated
		}
		host = net.IPv4(p[4], p[5], p[6], p[7]).String()
		port = int(p[8])<<8 | int(p[9])
		hdrEnd = 10
	case 0x03: // Domain
		if len(p) < 5 {
			return "", 0, nil, nil, errUDPTruncated
		}
		dl := int(p[4])
		if len(p) < 5+dl+2 {
			return "", 0, nil, nil, errUDPTruncated
		}
		host = string(p[5 : 5+dl])
		port = int(p[5+dl])<<8 | int(p[6+dl])
		hdrEnd = 5 + dl + 2
	case 0x04: // IPv6 — blocked.
		return "", 0, nil, nil, errUDPIPv6Blocked
	default:
		return "", 0, nil, nil, errUDPBadATYP
	}
	addrPortRaw = p[3:hdrEnd] // ATYP + DST.ADDR + DST.PORT
	payload = p[hdrEnd:]
	return host, port, addrPortRaw, payload, nil
}

// buildUDPDatagram prepends the RSV/FRAG bytes to a raw ATYP+ADDR+PORT slice
// and appends the payload, producing a full RFC 1928 §7 UDP datagram suitable
// for writing back to the client's relay socket.
func buildUDPDatagram(addrPortRaw []byte, payload []byte) []byte {
	out := make([]byte, 0, 3+len(addrPortRaw)+len(payload))
	out = append(out, 0x00, 0x00, 0x00) // RSV, RSV, FRAG
	out = append(out, addrPortRaw...)
	out = append(out, payload...)
	return out
}

// encodeUDPDatagram builds a full RFC 1928 §7 UDP datagram for host:port. IPv4
// literals use ATYP=0x01, everything else ATYP=0x03 (domain). Symmetric with
// parseUDPHeader; used by callers/tests that construct request datagrams.
func encodeUDPDatagram(host string, port int, payload []byte) []byte {
	var addrPort []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		ip4 := ip.To4()
		addrPort = []byte{0x01, ip4[0], ip4[1], ip4[2], ip4[3]}
	} else {
		addrPort = make([]byte, 0, 2+len(host))
		addrPort = append(addrPort, 0x03, byte(len(host)))
		addrPort = append(addrPort, host...)
	}
	addrPort = append(addrPort, byte(port>>8), byte(port&0xff))
	return buildUDPDatagram(addrPort, payload)
}

// udpFlow is one (client-src, dst) relay flow within an association.
type udpFlow struct {
	stream      *Stream
	clientAddr  *net.UDPAddr // where to write datagrams coming back from the dst
	addrPortRaw []byte       // ATYP+ADDR+PORT of the dst, for rebuilding reply headers
}

// handleUDPAssociate services a SOCKS5 UDP ASSOCIATE (CMD 0x03). clientConn is
// the control TCP connection; it is NOT closed here (the caller owns it) but its
// closure bounds the association lifetime. mux opens per-flow UDP streams to the
// server. This function blocks until the association ends.
func handleUDPAssociate(clientConn net.Conn, mux *Mux) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		// General SOCKS server failure.
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// Teardown below closes the relay socket too; this defer only covers
	// the early-return paths between here and then.
	defer func() { _ = relay.Close() }()

	relayPort := relay.LocalAddr().(*net.UDPAddr).Port
	// Reply: VER=05 REP=00 RSV=00 ATYP=01 BND.ADDR=127.0.0.1 BND.PORT.
	reply := []byte{
		0x05, 0x00, 0x00, 0x01,
		127, 0, 0, 1,
		byte(relayPort >> 8), byte(relayPort & 0xff),
	}
	if _, err := clientConn.Write(reply); err != nil {
		return
	}
	// The control conn now lives for the association; drop any read deadline.
	_ = clientConn.SetDeadline(time.Time{})

	var mu sync.Mutex
	flows := make(map[string]*udpFlow)
	var closed atomic.Bool

	teardown := func() {
		if closed.Swap(true) {
			return
		}
		// Closing the relay socket unblocks the ReadFromUDP loop below;
		// that is the point, and a close error still leaves it unblocked.
		_ = relay.Close()
		mu.Lock()
		for _, f := range flows {
			// Every flow is being abandoned with the association.
			_ = f.stream.Close()
		}
		flows = nil
		mu.Unlock()
	}
	defer teardown()

	// Watch the control conn: when the app closes the association (or the conn
	// drops), tear everything down. Reading returns on close/EOF.
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
		teardown()
	}()

	buf := make([]byte, udpRelayBufSize)
	for {
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			return // relay socket closed (teardown) or fatal read error
		}
		host, port, addrPortRaw, payload, perr := parseUDPHeader(buf[:n])
		if perr != nil {
			continue // drop malformed / IPv6 / fragmented datagrams
		}
		key := src.String() + "|" + host + ":" + strconv.Itoa(port)

		mu.Lock()
		f, ok := flows[key]
		if !ok {
			if flows == nil || len(flows) >= maxUDPFlows {
				mu.Unlock()
				continue
			}
			stream, oerr := mux.OpenStreamUDP(host, port)
			if oerr != nil {
				mu.Unlock()
				continue
			}
			f = &udpFlow{
				stream:      stream,
				clientAddr:  src,
				addrPortRaw: append([]byte(nil), addrPortRaw...),
			}
			flows[key] = f

			// Per-flow reader: datagrams from the server → client relay socket.
			go func(f *udpFlow, key string) {
				defer func() {
					mu.Lock()
					delete(flows, key)
					mu.Unlock()
					// The flow is over; the stream is unusable either way.
					_ = f.stream.Close()
				}()
				for {
					dg, rerr := f.stream.ReadDatagram()
					if len(dg) > 0 {
						out := buildUDPDatagram(f.addrPortRaw, dg)
						if _, werr := relay.WriteToUDP(out, f.clientAddr); werr != nil {
							return
						}
					}
					if rerr != nil {
						return
					}
				}
			}(f, key)
		}
		stream := f.stream
		mu.Unlock()

		if werr := stream.WriteDatagram(payload); werr != nil {
			// Stream is dead — evict so a later datagram re-opens it.
			mu.Lock()
			delete(flows, key)
			mu.Unlock()
			// The flow has been evicted; Stream.Close never fails.
			_ = stream.Close()
		}
	}
}
