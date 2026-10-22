package chamele0nx

import (
	"fmt"
	"strings"
	"testing"
)

// TestSNIPoolShape verifies the whitelist SNI pool is non-empty and
// every entry looks like a plausible hostname (contains a dot, no
// schema prefix, no trailing dot).
func TestSNIPoolShape(t *testing.T) {
	if len(substituteSNIPool) == 0 {
		t.Fatal("substituteSNIPool is empty")
	}
	if len(substituteSNIPool) < 10 {
		t.Errorf("substituteSNIPool has only %d entries, want ≥10 for distribution variance", len(substituteSNIPool))
	}
	for i, sni := range substituteSNIPool {
		if sni == "" {
			t.Errorf("pool[%d] is empty", i)
			continue
		}
		if !strings.Contains(sni, ".") {
			t.Errorf("pool[%d]=%q has no dot — not a hostname", i, sni)
		}
		if strings.HasPrefix(sni, "http://") || strings.HasPrefix(sni, "https://") {
			t.Errorf("pool[%d]=%q has schema prefix — SNI must be bare hostname", i, sni)
		}
		if strings.HasSuffix(sni, ".") {
			t.Errorf("pool[%d]=%q has trailing dot", i, sni)
		}
		if strings.ContainsAny(sni, " /\\:?") {
			t.Errorf("pool[%d]=%q contains invalid chars for SNI", i, sni)
		}
	}
}

// TestSNIPoolIsGlobalInfrastructure checks that the pool holds only
// globally used names. A name that is popular in one country but rare
// elsewhere is a poor choice: it narrows who the connection could
// plausibly belong to instead of widening it.
func TestSNIPoolIsGlobalInfrastructure(t *testing.T) {
	banned := []string{".ru", "yandex.", "vk.", "vkontakte.", "mail.ru", "webmoney."}
	for i, sni := range substituteSNIPool {
		low := strings.ToLower(sni)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("pool[%d]=%q is region-specific (%q), not global infrastructure", i, sni, b)
			}
		}
	}
}

// TestPickSubstituteSNIIsStickyPerIdentity pins the property that replaced
// per-connection rotation: the same client identity must always land on the
// same name.
//
// Rotation keyed the TLS session cache by a name that changed every dial, so
// a resumption ticket almost never matched and nearly every connection was a
// full handshake with no ticket — the absence this transport works elsewhere
// to avoid. A stable choice restores resumption and stops one address from
// claiming a couple of dozen brands in a short window.
func TestPickSubstituteSNIIsStickyPerIdentity(t *testing.T) {
	identity := []byte("aabbccddeeff00112233445566778899@vpn.example.com:443")

	first := pickSubstituteSNI(identity)
	for i := 0; i < 100; i++ {
		if got := pickSubstituteSNI(identity); got != first {
			t.Fatalf("call %d returned %q, want the sticky %q", i, got, first)
		}
	}
	if first == "" {
		t.Fatal("pickSubstituteSNI returned an empty name")
	}

	// A different identity should generally land elsewhere; with a pool this
	// size a handful of identities must not all collapse onto one name.
	seen := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		seen[pickSubstituteSNI([]byte(strings.Repeat("a", i%7)+string(rune('a'+i%26))+"@host"))] = struct{}{}
	}
	if len(seen) < 5 {
		t.Errorf("200 identities produced only %d distinct names — the choice has collapsed", len(seen))
	}
}

// TestPickSubstituteSNIDistribution verifies the whole pool stays reachable:
// a fleet of clients should spread across it rather than piling onto one name.
func TestPickSubstituteSNIDistribution(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < 20000; i++ {
		seen[pickSubstituteSNI([]byte(fmt.Sprintf("secret-%d@server", i)))]++
	}
	if len(seen) != len(substituteSNIPool) {
		t.Errorf("only %d/%d names reached over 20000 identities — distribution bug",
			len(seen), len(substituteSNIPool))
	}
	for name, count := range seen {
		if count < 100 {
			t.Errorf("name %q chosen only %d times in 20000 identities — distribution skew", name, count)
		}
	}
}

// TestPickSubstituteSNIEmptyIdentity: a degenerate identity must still yield
// a usable name rather than an empty string.
func TestPickSubstituteSNIEmptyIdentity(t *testing.T) {
	if got := pickSubstituteSNI(nil); got == "" {
		t.Error("nil identity returned an empty name")
	}
	if got := pickSubstituteSNI([]byte{}); got == "" {
		t.Error("empty identity returned an empty name")
	}
}
