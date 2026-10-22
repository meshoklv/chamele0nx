package chamele0nx

// cover_saas_http2.go — registration of the "saas-http2" cover profile.
//
// This is a registration shim. The actual Open() implementation still
// lives inline in Transport.connect(): that function is ~400 lines of
// uTLS + HTTP/2 client + POST pipe + auth wiring, and carving it out
// cleanly without regressing 90 tests is a separate change.
//
// For now this file exists to:
//
//   1. Reserve the name "saas-http2" in the registry so TestCoverRegistry
//      (and the `RegisteredCoverIDs` diagnostic)
//      know the current Chamele0nX build can speak HTTP/2+uTLS.
//   2. Give callers an identifier to put in endpoint.Params["cover"]
//      today — even if we still route through the inline path, clients
//      that set "cover"="saas-http2" get validated up front ("yes, this
//      build supports that mask") and clients that ask for a cover
//      this build does not have get the proper "not available in this
//      build" error, not a silent fallthrough.
//   3. Pin the one-liner Describe() string for logs, so an operator
//      reading the system journal sees "saas-http2" with a
//      human-readable description instead of a cryptic
//      "HTTP/2 client dial".
//
// When a second cover profile is added, this file is the reference
// skeleton for it: the same registration pattern with a different Open()
// body. And when the inline connect() body eventually moves into
// saasHTTP2Cover.Open, the shim here grows into the real cover with no
// RegisterCover surgery required.

import (
	"context"
	"errors"
	"net"
)

// saasHTTP2Cover is the current default Chamele0nX masquerade: uTLS
// Chrome 146 handshake over TCP/443, HTTP/2 POST to a SaaS events API,
// TLS record sizes and burst timings shaped against a real dashboard
// traffic profile. See the comments at the top of chamele0nx.go and
// Transport.connect() for the full data path.
//
// The struct is intentionally empty — cover profiles are stateless
// singletons. Per-connection state (profile personalization, session
// cache, handshake counters) lives either on *Transport or on whatever
// net.Conn Open returns, never on the CoverProfile itself. That lets
// a single saasHTTP2Cover instance serve every concurrent dial without
// any locking.
type saasHTTP2Cover struct{}

// ID returns the stable wire identifier for this cover profile. Clients
// put this exact string into endpoint.Params["cover"] to select it.
func (saasHTTP2Cover) ID() string { return "saas-http2" }

// Describe returns the human-readable one-liner for log messages.
func (saasHTTP2Cover) Describe() string {
	return "HTTP/2 SaaS dashboard (uTLS Chrome 146 + TLS record shaping)"
}

// Open is currently a stub. The real HTTP/2 + uTLS + POST logic still
// lives inline in Transport.connect() — see the top-of-file comment
// for why. Transport.connect() checks ResolveCover first, verifies
// the requested cover is registered, then falls through to the inline
// path. Calling Open() directly today returns a clear error; that
// error goes away once the inline body moves here.
//
// CONTRACT for the future: this method will take OpenOptions, run
// the full dialChamele0nXUTLS → ShapedConn → HTTP/2 client → POST pipe
// sequence, and return a net.Conn that the caller can wrap with mux
// and crypto. Nothing else in Chamele0nX should need to know what this
// function does.
func (saasHTTP2Cover) Open(ctx context.Context, opts OpenOptions) (net.Conn, error) {
	return nil, errors.New("chamele0nx: saas-http2 cover is opened by Transport.connect, not through CoverProfile.Open")
}

func init() {
	RegisterCover(saasHTTP2Cover{})
}
