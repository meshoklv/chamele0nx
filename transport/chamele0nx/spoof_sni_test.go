package chamele0nx

import (
	"strings"
	"testing"

	"github.com/meshoklv/chamele0nx/transport"
)

const testSecretHex = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff"

func spoofEndpoint(params map[string]string) transport.Endpoint {
	base := map[string]string{
		"chameleon_addr": "vpn.example.com:443",
		"user_secret":    testSecretHex,
	}
	for k, v := range params {
		base[k] = v
	}
	return transport.Endpoint{Params: base}
}

// TestSpoofSNIRequiresPin: substituting a name turns off certificate name
// verification, which is only safe when the key is pinned. Accepting the name
// without a pin would leave the client trivially interceptable.
func TestSpoofSNIRequiresPin(t *testing.T) {
	err := validateChamele0nXParams(spoofEndpoint(map[string]string{
		"chameleon_spoof_sni": "cdn.example.net",
	}))
	if err == nil {
		t.Fatal("a substitute name was accepted with no key pin")
	}
	if !strings.Contains(err.Error(), "chameleon_pubkey_pin") {
		t.Errorf("error does not explain the missing pin: %v", err)
	}

	// With a pin it is accepted.
	if err := validateChamele0nXParams(spoofEndpoint(map[string]string{
		"chameleon_spoof_sni":  "cdn.example.net",
		"chameleon_pubkey_pin": strings.Repeat("ab", 32),
	})); err != nil {
		t.Errorf("a pinned substitute name was rejected: %v", err)
	}
}

// TestSpoofSNIRejectsMalformedNames keeps anything that is not a hostname off
// the wire — the value goes straight into a ClientHello.
func TestSpoofSNIRejectsMalformedNames(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	for _, bad := range []string{
		"https://example.com",   // scheme
		"example.com:443",       // port
		"exa mple.example.com",  // space
		"bad..example.com",      // empty label
		"-bad.example.com",      // leading hyphen
		"bad-.example.com",      // trailing hyphen
		"host.example.com.",     // trailing dot
		"exam_ple.example.com",  // underscore
		strings.Repeat("a", 64), // label too long
		strings.Repeat("a.", 200),
		"192.0.2.1", // an address is not a DNS name (RFC 6066 5.1)
		"::1",       // nor is an IPv6 literal
		"localhost", // a single label is not a DNS name either
	} {
		err := validateChamele0nXParams(spoofEndpoint(map[string]string{
			"chameleon_spoof_sni":  bad,
			"chameleon_pubkey_pin": pin,
		}))
		if err == nil {
			t.Errorf("accepted malformed name %q", bad)
		}
	}

	for _, good := range []string{
		"example.com",
		"cdn.example.net",
		"a.b.c.example.org",
		"xn--80ak6aa92e.example.com",
		"host123.example.com",
	} {
		if err := validateChamele0nXParams(spoofEndpoint(map[string]string{
			"chameleon_spoof_sni":  good,
			"chameleon_pubkey_pin": pin,
		})); err != nil {
			t.Errorf("rejected valid name %q: %v", good, err)
		}
	}
}

// TestSpoofSNIRejectedWhenSubstitutionIsOff: naming a substitute while
// substitution is switched off means the value would silently never be used.
// Say so instead of accepting it.
func TestSpoofSNIRejectedWhenSubstitutionIsOff(t *testing.T) {
	err := validateChamele0nXParams(spoofEndpoint(map[string]string{
		"chameleon_spoof_sni":  "cdn.example.net",
		"chameleon_pubkey_pin": strings.Repeat("ab", 32),
		"chameleon_spoof":      "off",
	}))
	if err == nil {
		t.Fatal("a substitute name was accepted with substitution switched off")
	}
	if !strings.Contains(err.Error(), "chameleon_spoof=off") {
		t.Errorf("error does not explain the contradiction: %v", err)
	}
}

// TestSubstitutionIdentityIsStableAndSeparating: the identity behind the
// sticky choice must not change between reconnects, and two users of one
// server must not share it.
func TestSubstitutionIdentityIsStableAndSeparating(t *testing.T) {
	a := spoofEndpoint(nil)
	// Two endpoints built separately from the same parameters must agree:
	// this is what makes the choice survive a reconnect.
	sameAgain := spoofEndpoint(nil)
	if string(substitutionIdentity(a)) != string(substitutionIdentity(sameAgain)) {
		t.Error("identity is not stable across endpoints with identical parameters")
	}

	other := spoofEndpoint(map[string]string{"user_secret": strings.Repeat("cd", 32)})
	if string(substitutionIdentity(a)) == string(substitutionIdentity(other)) {
		t.Error("two different secrets produced the same identity")
	}

	elsewhere := spoofEndpoint(map[string]string{"chameleon_addr": "other.example.com:443"})
	if string(substitutionIdentity(a)) == string(substitutionIdentity(elsewhere)) {
		t.Error("two different servers produced the same identity")
	}
}

// TestSpoofSNIAbsentIsStillValid: the parameter is optional, and an endpoint
// that never mentions it must keep working exactly as before.
func TestSpoofSNIAbsentIsStillValid(t *testing.T) {
	if err := validateChamele0nXParams(spoofEndpoint(nil)); err != nil {
		t.Errorf("an endpoint without the parameter was rejected: %v", err)
	}
}
