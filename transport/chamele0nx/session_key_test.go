package chamele0nx

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// TestSessionKeyGuardConcurrentUseAndDestroy is the regression test for the
// data race on the session key. It deliberately does what the tunnel does at
// teardown — wipe the key while other goroutines are inside the cipher — and
// under `go test -race` it fails on the unguarded version.
//
// The plain Zeroize this replaced was never caught by the race detector,
// because the detector only reports conflicting accesses that actually
// happened, and no existing test holds a goroutine inside AES at the instant
// Close runs. This one is built to hold that overlap open.
func TestSessionKeyGuardConcurrentUseAndDestroy(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	g := newSessionKeyGuard(key)

	const workers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			payload := []byte("frame payload that keeps the cipher busy")
			for j := 0; j < 200; j++ {
				ct, err := g.encrypt(payload)
				if err != nil {
					// Once destroyed, every call must fail this way and
					// never with a zeroed key.
					if !errors.Is(err, errSessionClosed) {
						t.Errorf("encrypt failed with %v, want errSessionClosed", err)
					}
					return
				}
				pt, err := g.decrypt(ct)
				if err != nil {
					if !errors.Is(err, errSessionClosed) {
						t.Errorf("decrypt failed with %v, want errSessionClosed", err)
					}
					return
				}
				if !bytes.Equal(pt, payload) {
					t.Error("round trip returned different bytes — the key changed mid-operation")
					return
				}
			}
		}()
	}

	// Destroy from another goroutine while the workers are running.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		g.destroy()
	}()

	close(start)
	wg.Wait()

	// After destruction the key buffer is wiped and further use is refused.
	if !bytes.Equal(key, make([]byte, 32)) {
		t.Error("key material was not wiped")
	}
	if _, err := g.encrypt([]byte("x")); !errors.Is(err, errSessionClosed) {
		t.Errorf("encrypt after destroy returned %v, want errSessionClosed", err)
	}
	if _, err := g.decrypt([]byte("x")); !errors.Is(err, errSessionClosed) {
		t.Errorf("decrypt after destroy returned %v, want errSessionClosed", err)
	}
}

// TestSessionKeyGuardDestroyIsIdempotent covers the teardown paths that can
// run twice — Tunnel.Close is documented as idempotent, and the server wipes
// through a defer that may follow an explicit close.
func TestSessionKeyGuardDestroyIsIdempotent(t *testing.T) {
	g := newSessionKeyGuard(bytes.Repeat([]byte{0x11}, 32))
	g.destroy()
	g.destroy() // must not panic on the now-nil key
}

// TestSessionKeyGuardRoundTrip is the ordinary path: the guard must not
// change what the cipher does.
func TestSessionKeyGuardRoundTrip(t *testing.T) {
	g := newSessionKeyGuard(bytes.Repeat([]byte{0x33}, 32))
	payload := []byte("hello tunnel")

	ct, err := g.encrypt(payload)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ct, payload) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := g.decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("round trip returned %q, want %q", pt, payload)
	}
}
