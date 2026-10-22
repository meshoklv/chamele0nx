package chamele0nx

import (
	"errors"
	"sync"

	"github.com/meshoklv/chamele0nx/internal/chcrypto"
)

// errSessionClosed is returned when a frame is encrypted or decrypted after
// the session key has been wiped. It means the tunnel is finished, not that
// the data was bad.
var errSessionClosed = errors.New("chamele0nx: session key destroyed")

// sessionKeyGuard owns an AEAD session key and makes wiping it safe.
//
// Wiping used to be a plain Zeroize on the key slice at teardown, while other
// goroutines were still reading the same backing array inside Encrypt and
// Decrypt: on the client, readLoop and the mux write closure; on the server,
// per-stream goroutines that outlive an individual write. That is a data race
// on the key buffer, which the Go memory model leaves undefined — and in
// practice it can hand a cipher a half-zeroed key.
//
// The race detector never flagged it, and that is not evidence of absence: it
// only reports conflicting accesses that actually happened in a run, and no
// test holds a goroutine inside AES at the instant teardown runs. The window
// is real on the reconnect and shutdown-timeout paths, where a tunnel is
// closed while relay handlers are still draining.
//
// A read lock is held for the duration of each cipher operation and the write
// lock for the wipe, so the key cannot be destroyed underneath a user. Late
// arrivals get errSessionClosed instead of a zeroed key. The cost is one
// RWMutex read lock per frame, which is nothing beside the AES-GCM pass it
// guards.
type sessionKeyGuard struct {
	mu  sync.RWMutex
	key []byte // nil once destroyed
}

func newSessionKeyGuard(key []byte) *sessionKeyGuard {
	return &sessionKeyGuard{key: key}
}

// encrypt seals payload under the session key.
func (s *sessionKeyGuard) encrypt(payload []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, errSessionClosed
	}
	return chcrypto.Encrypt(s.key, payload)
}

// decrypt opens ciphertext under the session key.
func (s *sessionKeyGuard) decrypt(ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, errSessionClosed
	}
	return chcrypto.Decrypt(s.key, ciphertext)
}

// destroy wipes the key. It blocks until every in-flight cipher operation has
// finished, and is safe to call more than once.
func (s *sessionKeyGuard) destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return
	}
	chcrypto.Zeroize(s.key)
	s.key = nil
}
