package chamele0nx

// cover_test.go — regression tests for the Cover Profile abstraction.
// These tests pin the registry contract so that adding further cover
// profiles later cannot accidentally break the default path.

import (
	"context"
	"strings"
	"testing"

	"github.com/meshoklv/chamele0nx/transport"
)

// TestCoverRegistryContainsDefault verifies that after package init() the
// registry has "saas-http2" wired up. If a future refactor moves saas-http2
// registration out of the package init() chain (e.g. into a blank-imported
// sub-package) this test catches it before clients see "cover profile not
// registered" errors in the field.
func TestCoverRegistryContainsDefault(t *testing.T) {
	cp, err := ResolveCover(DefaultCoverID)
	if err != nil {
		t.Fatalf("ResolveCover(%q) failed: %v", DefaultCoverID, err)
	}
	if cp == nil {
		t.Fatalf("ResolveCover(%q) returned nil CoverProfile", DefaultCoverID)
	}
	if cp.ID() != DefaultCoverID {
		t.Errorf("registered cover returned mismatched ID: got %q, want %q", cp.ID(), DefaultCoverID)
	}
	if cp.Describe() == "" {
		t.Error("Describe() returned empty — every cover must provide a human-readable one-liner")
	}
}

// TestCoverRegistryEmptyIDFallback verifies that ResolveCover("") falls
// back to DefaultCoverID. This path is hit every time an endpoint
// written before cover profiles existed (no cover param in its blob)
// goes through connect() — if we break the fallback, every legacy
// invite dies simultaneously.
func TestCoverRegistryEmptyIDFallback(t *testing.T) {
	cpEmpty, err := ResolveCover("")
	if err != nil {
		t.Fatalf("ResolveCover(\"\") should fall back to default, got error: %v", err)
	}
	cpDefault, _ := ResolveCover(DefaultCoverID)
	if cpEmpty != cpDefault {
		t.Errorf("ResolveCover(\"\") returned a different instance than ResolveCover(%q)", DefaultCoverID)
	}
}

// TestCoverRegistryUnknownIDRejected verifies that ResolveCover on an
// unregistered ID returns a descriptive error listing every registered
// profile. That error is what clients see in the field when a config
// asks for a mask this build doesn't include — it must be self-
// explanatory so an operator can diagnose without reading source.
func TestCoverRegistryUnknownIDRejected(t *testing.T) {
	_, err := ResolveCover("definitely-not-a-real-cover-profile")
	if err == nil {
		t.Fatal("ResolveCover on unknown ID should return error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not registered") {
		t.Errorf("error message should explain why: %q", msg)
	}
	// The diagnostic path should list what IS available so operators
	// can see what this build supports without grepping source.
	if !strings.Contains(msg, DefaultCoverID) {
		t.Errorf("error message should list registered covers including %q, got: %q", DefaultCoverID, msg)
	}
}

// TestRegisteredCoverIDsIsSorted verifies the snapshot is sorted. Sort
// order matters because the list surfaces in log diagnostics, and
// operators compare builds by eye and expect stable ordering.
func TestRegisteredCoverIDsIsSorted(t *testing.T) {
	ids := RegisteredCoverIDs()
	if len(ids) == 0 {
		t.Fatal("RegisteredCoverIDs returned empty — package init did not run")
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Errorf("RegisteredCoverIDs not sorted: %v", ids)
			break
		}
	}
	// Must include the default at a minimum.
	found := false
	for _, id := range ids {
		if id == DefaultCoverID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("default cover %q missing from RegisteredCoverIDs: %v", DefaultCoverID, ids)
	}
}

// TestValidateChamele0nXParamsRejectsUnknownCover verifies that endpoint
// validation fails fast when an invite specifies a cover profile that
// this build doesn't ship. Catches the "client is ahead of server build"
// and "server is ahead of client build" edge cases up front, before
// the reconnect loop spends cycles on a handshake it can't complete.
func TestValidateChamele0nXParamsRejectsUnknownCover(t *testing.T) {
	base := transport.Endpoint{
		ID:        "srv1",
		Transport: "chamele0nx",
		Params: map[string]string{
			"chameleon_addr": "vpn.example.com:443",
			"user_secret":    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
	}

	// Unknown cover → error with useful diagnostic.
	bad := base
	bad.Params = copyParams(base.Params)
	bad.Params["cover"] = "not-a-real-mask"
	if err := validateChamele0nXParams(bad); err == nil {
		t.Error("validateChamele0nXParams should reject unknown cover profile")
	} else if !strings.Contains(err.Error(), "not-a-real-mask") {
		t.Errorf("error should mention the offending cover ID, got: %v", err)
	}

	// Default cover omitted → ok (legacy path must keep working).
	if err := validateChamele0nXParams(base); err != nil {
		t.Errorf("validateChamele0nXParams should accept endpoints without cover param (legacy compat), got: %v", err)
	}

	// Default cover explicitly named → ok.
	ok := base
	ok.Params = copyParams(base.Params)
	ok.Params["cover"] = DefaultCoverID
	if err := validateChamele0nXParams(ok); err != nil {
		t.Errorf("validateChamele0nXParams should accept cover=%q, got: %v", DefaultCoverID, err)
	}
}

// TestSaasHTTP2CoverOpenStub pins the stub behaviour, so that whoever
// wires Open() up later cannot forget to remove this guard. When the
// stub is replaced with a real implementation, this test gets deleted
// rather than updated to pass — the behaviour change is the whole
// point, and leaving a "wait for the new error message" test behind
// would just slow future work down.
func TestSaasHTTP2CoverOpenStub(t *testing.T) {
	cp, err := ResolveCover("saas-http2")
	if err != nil {
		t.Fatalf("ResolveCover: %v", err)
	}
	_, err = cp.Open(context.Background(), OpenOptions{})
	if err == nil {
		t.Fatal("saas-http2 Open() should report that the cover is opened by Transport.connect; if it now succeeds, this test needs updating")
	}
}

// copyParams returns a shallow copy of a params map so tests can mutate
// their own copy without touching the base case.
func copyParams(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
