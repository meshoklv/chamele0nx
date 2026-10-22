package chamele0nx

import (
	"context"
	"crypto/tls"
	"net"

	reqlib "github.com/imroc/req/v3"
	"github.com/imroc/req/v3/http2"
)

// chromePseudoHeaderOrder is the order in which Chrome emits HTTP/2
// pseudo-headers (m, a, s, p). Go's stdlib sends :method :scheme
// :authority :path; detectors fingerprint on exactly this difference.
var chromePseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

// h2Conn presents an already-handshaked, record-shaped connection to the
// HTTP/2 client as a finished TLS connection that negotiated "h2". The TLS
// handshake itself was done by our own uTLS dial, so the state reported
// here only has to tell the client which protocol to speak; it carries no
// peer certificate information and nothing reads any.
type h2Conn struct {
	net.Conn
}

func (h2Conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:            tls.VersionTLS13,
		HandshakeComplete:  true,
		NegotiatedProtocol: "h2",
	}
}
func (h2Conn) Handshake() error                       { return nil }
func (h2Conn) HandshakeContext(context.Context) error { return nil }

// newChromeH2Transport builds an HTTP/2-only client transport whose
// connection preface matches Chrome 120-146 (per the scrapfly.io HTTP/2
// fingerprint guide and the Akamai whitepaper):
//
//   - SETTINGS: exactly four entries, in this order — HEADER_TABLE_SIZE
//     65536, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 6291456, MAX_HEADER_LIST_SIZE
//     262144. MAX_CONCURRENT_STREAMS and MAX_FRAME_SIZE are not advertised,
//     as Chrome does not.
//   - connection-level WINDOW_UPDATE of 15663105 right after SETTINGS.
//   - pseudo-header order m, a, s, p (set per request via
//     reqlib.PseudoHeaderOderKey; see chromePseudoHeaderOrder).
//
// dial must return an already-handshaked connection; the transport does no
// TLS of its own. The caller sets header order per request with
// reqlib.HeaderOderKey.
func newChromeH2Transport(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *reqlib.Transport {
	t := reqlib.C().
		DisableCompression().
		GetTransport()
	t.SetDialTLS(func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return h2Conn{conn}, nil
	})
	t.EnableForceHTTP2()
	t.SetHTTP2SettingsFrame(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	)
	t.SetHTTP2ConnectionFlow(15663105)
	return t
}
