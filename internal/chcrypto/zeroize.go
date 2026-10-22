package chcrypto

import "runtime"

// Zeroize overwrites a byte slice with zeros to reduce the window during
// which secret material is recoverable from process memory.
//
// Uses runtime.KeepAlive to prevent the compiler from optimizing away
// the zero-writes as dead stores when the slice is not read afterward.
//
// Limitation: Go's garbage collector may copy heap objects during
// compaction, leaving stale copies in freed pages. Zeroization is therefore
// best-effort defense-in-depth — it eliminates the primary copy but cannot
// guarantee that no residual copies exist. For the strongest protection
// against physical/forensic attacks, combine with OS-level encrypted memory
// or locked pages (mlock) where available.
//
// Call this via defer or explicit cleanup whenever a secret (PSK, private
// key, derived key material) is no longer needed.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b)
}
