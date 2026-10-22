package chamele0nx

import (
	"crypto/sha256"
	"encoding/binary"
)

// SNI selection for the substitution mode.
//
// Some inspection deployments decide whether to keep forwarding a flow
// from the ClientHello alone, and in particular from the server name in
// it, rather than from anything about the traffic that follows. Where
// that is the case, no amount of record shaping helps: the decision has
// already been made before the first byte of application data. The only
// lever left is which name the handshake advertises.
//
// This file holds a small pool of names to advertise in that situation.
// The pool is deliberately generic: widely used global infrastructure
// that any device contacts as background noise, spread across several
// providers so that connections cannot be grouped by the one CDN they
// all name. Which names are useful is a local, perishable question, and
// operators who care should supply their own rather than trusting this
// list to stay current. A name that stops working is worse than useless
// to whoever kept using it.
//
// Substitution is off unless the endpoint supplies `chameleon_pubkey_pin`
// (see validateChamele0nXParams and connect in chamele0nx.go). Without a
// pin, certificate validation would fail on the name mismatch, since
// TLS would be told to verify one name while the server presents a
// certificate for another. With a pin, name verification is replaced by
// a constant-time comparison of the peer's SubjectPublicKeyInfo digest
// against the pinned value, so an interceptor needs the server's private
// key rather than merely a certificate for the advertised name.

// substituteSNIPool is the pool of names the substitution mode draws from.
// pickSubstituteSNI selects one deterministically from the connection
// seed. Order carries no meaning.
var substituteSNIPool = []string{
	// --- Microsoft infra (always in background on any Windows device) ---
	"microsoft.com",
	"windows.com",
	"xbox.com",
	"xboxlive.com",
	"visualstudio.com",
	"bing.com",

	// --- Apple infra (always in background on any iOS / macOS device) ---
	"apple.com",

	// --- Software-distribution / update CDNs (every OS hits these) ---
	"cdnjs.com",         // Cloudflare JS CDN, used by tens of thousands of sites
	"bootstrapcdn.com",  // Bootstrap CSS/JS CDN
	"fedoraproject.org", // Linux distro update
	"centos.org",        // Linux distro update
	"apache.org",        // Apache Software Foundation

	// --- Developer tooling (stackexchange network, dev CDNs) ---
	"stackoverflow.com",
	"stackexchange.com",
	"superuser.com",
	"askubuntu.com",
	"bitbucket.org",
	"sublimetext.com",

	// --- Enterprise SaaS (common background traffic on corporate devices) ---
	"atlassian.com",
	"asana.com",
	"trello.com",
	"dropbox.com",
	"box.com",
	"webex.com",

	// --- Adobe ecosystem (Creative Cloud, background sync) ---
	"adobe.com",
	"adobelogin.com",

	// --- Globally ubiquitous reference / media ---
	"wikipedia.org",
	"w3.org",
	"cisco.com",
	"vmware.com",
	"spotify.com",
}

// pickSubstituteSNI returns one name from substituteSNIPool, chosen once and
// for all from a client's own identity rather than freshly per connection.
//
// The seed used to be the per-connection random value, so the name changed on
// every dial. That looked like diversity and was not:
//
//   - The TLS session cache is keyed by server name. With N names in the pool
//     a resumption ticket matched roughly one dial in N, so nearly every
//     connection was a full handshake with no ticket — the very absence this
//     transport works elsewhere to avoid. A returning visitor who never
//     resumes is itself the anomaly.
//   - One address answering to a couple of dozen well-known brands over a
//     short window is a stranger shape than one address that consistently
//     claims a single name.
//   - No comparable transport rotates. REALITY, Trojan and NaiveProxy each
//     pin one name for the life of a deployment.
//
// The name is therefore derived from material that is stable for this client
// and this server, and identical across reconnects. Different users of the
// same server land on different names, so the pool still spreads a fleet out
// rather than making every deployment claim the same brand.
//
// An operator who controls a name — one that actually resolves to them, or
// one their own front terminates — should pass it explicitly instead, which
// is strictly better than any pool entry. This is the fallback for those who
// do not.
func pickSubstituteSNI(identity []byte) string {
	if len(substituteSNIPool) == 0 {
		// Defensive fallback. Should never trigger — pool is hard-coded.
		return "microsoft.com"
	}
	sum := sha256.Sum256(append([]byte("chamele0nx-sni-v1"), identity...))
	idx := binary.BigEndian.Uint64(sum[:8]) % uint64(len(substituteSNIPool))
	return substituteSNIPool[idx]
}
