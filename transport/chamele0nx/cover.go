package chamele0nx

// cover.go — the Cover Profile abstraction.
//
// The idea. A "cover profile" is the complete masquerade scenario Chamele0nX
// wears on a given connection: what wire protocol we speak, what handshake
// we perform, what fingerprint we emit, what traffic shape we impose. The
// cover profile shipped in this repository is "saas-http2": a uTLS
// Chrome 146 handshake, an HTTP/2 POST, and TLS record shaping against a
// SaaS dashboard profile. Every other Chamele0nX design is a variation on
// the same theme.
//
// A second cover profile could look completely different — say a call-like
// cover that carries the same payload inside a UDP media session, with its
// own handshake sequence and its own pacing rules. From the caller's point
// of view it is still the same Transport returning a net.Conn on which the
// same mux, crypto, and auth stack runs. That commonality is exactly what
// this abstraction captures.
//
// Why not just add a second transport? Because two transports are not one
// protocol. Two transports mean two independent release cycles, two bug
// surfaces, two crypto audits, and two mobile bindings. The goal here is a
// single protocol, not two products glued together. Cover profiles are
// masks on one face, not two faces: a shared core (mux, crypto, auth,
// framing, session management) and a swappable mask (handshake,
// fingerprint, wire shape).
//
// Adding a further mask then costs one file — register it in init() and
// implement Open — and everything built on top of the registry applies to
// it for free. See docs/en/SPEC.md for the wire contract a cover must meet.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/meshoklv/chamele0nx/transport"
)

// CoverProfile is the contract every Chamele0nX masquerade must satisfy.
//
// Implementations are registered in the package-global registry via
// RegisterCover at init() time. Transport.connect() picks one by name
// from endpoint.Params["cover"] (default: "saas-http2") and delegates
// the "get me a tunneled net.Conn" job to it. Everything above — mux,
// encryption, auth, framing — stays common and cover-agnostic.
//
// Cover profiles are stateless singletons: all per-connection state
// (seeds, session tickets, any cover-specific credentials, personalized
// profiles) lives inside the net.Conn that Open returns, never on the
// CoverProfile itself. This means a CoverProfile implementation can
// be shared across every concurrent dial without locking.
type CoverProfile interface {
	// ID returns the cover profile identifier. Must be stable across
	// builds and match what clients put in endpoint.Params["cover"].
	// Lowercase, kebab-case, ASCII — for example "saas-http2", or
	// "cover-b" for a second mask.
	ID() string

	// Describe returns a human-readable one-liner used in logs and
	// error messages. e.g. "HTTP/2 SaaS dashboard (Chrome 146 uTLS)".
	Describe() string

	// Open establishes the tunnel conn for one client→server session.
	// The returned net.Conn must be full-duplex and deliver framed
	// bytes — the caller will layer mux, crypto, and auth on top of
	// it without knowing anything about the underlying wire protocol.
	//
	// Open is responsible for:
	//   - Parsing endpoint params specific to this cover profile
	//     (for example "chameleon_sni" for saas-http2; a UDP-based
	//     cover would read its own rendezvous params here)
	//   - Performing the full handshake, whatever that means for this
	//     wire protocol
	//   - Applying any cover-specific traffic shaping (ShapedConn,
	//     datagram pacing, whatever the masquerade demands)
	//   - Returning a net.Conn whose Read and Write move payload
	//     bytes cleanly; the caller treats it as a duplex pipe
	//
	// Open should NOT:
	//   - Start mux channels (caller's job)
	//   - Do auth validation (caller's job — cover profiles carry
	//     auth-opaque bytes)
	//   - Encrypt the payload beyond what the wire protocol itself
	//     mandates (Chamele0nX runs its own AES-GCM envelope on top
	//     of every cover; the cover's own transport security exists
	//     for the masquerade, not for confidentiality of our payload)
	//
	// The returned net.Conn's Close must tear down the whole
	// cover-specific stack — for saas-http2 that is TCP → TLS → the
	// HTTP/2 pipe. Callers will only call Close once per Open; there
	// is no reuse.
	Open(ctx context.Context, opts OpenOptions) (net.Conn, error)
}

// OpenOptions bundles everything a CoverProfile.Open needs from the
// surrounding Transport. Fields are additive: new cover profiles that
// need extra inputs get them here, not via side channels on the
// Transport struct, so the cover profile surface stays explicit.
type OpenOptions struct {
	// Endpoint is the full transport.Endpoint passed into
	// Transport.Connect — cover profiles read their own params from
	// Endpoint.Params (for example "chameleon_sni").
	Endpoint transport.Endpoint

	// ClientSeed is the per-connection randomness seed that every
	// cover-specific fingerprint jitter (record sizes, inter-burst
	// pause, User-Agent pick, SNI pool pick) must derive from.
	// Shared across profile personalization, the uTLS cache, and the
	// burst shaper — kept as one seed so the whole session looks like
	// one coherent fake identity.
	ClientSeed uint64

	// Profile is the already-personalized SiteProfile for THIS
	// connection (post-PersonalizeFor). Cover profiles that do
	// their own shaping use this; a cover that paces by some other
	// rule — say a fixed datagram size — can ignore it.
	Profile *SiteProfile

	// Transport is the parent *Transport — cover profiles that
	// need access to the shared sessionCache or handshake counters
	// (currently only saas-http2) reach it via this handle. Do NOT
	// store this pointer past Open returning.
	Transport *Transport
}

// coverRegistry is the package-global name→CoverProfile map, guarded
// by a RWMutex so registrations from init() funcs of sibling files
// (or, later, blank-imported cover sub-packages) can't race with
// lookups from Transport.connect().
//
// Use RegisterCover to populate, ResolveCover to read. There is no
// Unregister — cover profiles are meant to live for the whole process
// lifetime.
var (
	coverRegistryMu sync.RWMutex
	coverRegistry   = map[string]CoverProfile{}
)

// DefaultCoverID is the cover profile used when an endpoint doesn't
// specify one in params. It points at saas-http2, the original
// Chamele0nX path — chosen so every invite blob, mobile config, and
// integration test written before cover profiles existed keeps working
// without changes.
//
// It is a compile-time constant today. A future revision could let an
// operator push a different default out of band, moving existing
// clients onto whichever cover profile is surviving best in the field.
// See docs/en/ROADMAP.md.
const DefaultCoverID = "saas-http2"

// RegisterCover installs a CoverProfile into the registry. Safe to call
// from init() of multiple files concurrently. Panics on duplicate ID —
// ID collisions indicate a build-time programmer error (two files both
// claiming the same mask), not a runtime condition.
//
// Typical usage at the bottom of a cover_*.go file:
//
//	func init() {
//	    RegisterCover(&saasHTTP2Cover{})
//	}
//
// The global registry is intentionally process-scoped (not
// per-Transport) so tests that create multiple Transport instances
// don't need to re-register every cover on each Transport.
func RegisterCover(c CoverProfile) {
	if c == nil {
		panic("chamele0nx: RegisterCover called with nil CoverProfile")
	}
	id := c.ID()
	if id == "" {
		panic("chamele0nx: RegisterCover called with cover that has empty ID")
	}
	coverRegistryMu.Lock()
	defer coverRegistryMu.Unlock()
	if _, dup := coverRegistry[id]; dup {
		panic(fmt.Sprintf("chamele0nx: cover %q registered twice", id))
	}
	coverRegistry[id] = c
}

// ResolveCover looks up a cover profile by ID. Returns a descriptive
// error if the ID isn't registered — this is the surface that explains
// "you asked for cover X, but this build only includes Y, Z" to the
// end user / log reader.
func ResolveCover(id string) (CoverProfile, error) {
	if id == "" {
		id = DefaultCoverID
	}
	coverRegistryMu.RLock()
	defer coverRegistryMu.RUnlock()
	cp, ok := coverRegistry[id]
	if !ok {
		return nil, fmt.Errorf("chamele0nx: cover profile %q not registered; available: %v", id, registeredCoverIDsLocked())
	}
	return cp, nil
}

// RegisteredCoverIDs returns a sorted snapshot of all cover profile
// IDs currently registered. Useful for diagnostics and for CLI
// `--list-covers` flags. The returned slice is a fresh copy — safe for
// the caller to mutate.
func RegisteredCoverIDs() []string {
	coverRegistryMu.RLock()
	defer coverRegistryMu.RUnlock()
	return registeredCoverIDsLocked()
}

// registeredCoverIDsLocked is the lock-already-held helper used by
// both RegisteredCoverIDs and ResolveCover's error path. Keeping the
// sort.Strings here means every diagnostic surface prints IDs in the
// same deterministic order.
func registeredCoverIDsLocked() []string {
	ids := make([]string, 0, len(coverRegistry))
	for id := range coverRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
