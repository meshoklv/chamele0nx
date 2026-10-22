package chcrypto

import "testing"

func TestZeroize(t *testing.T) {
	secret := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	Zeroize(secret)

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got 0x%02X", i, b)
		}
	}
}

func TestZeroize_Empty(t *testing.T) {
	// Must not panic on empty slice.
	Zeroize([]byte{})
}

func TestZeroize_Nil(t *testing.T) {
	// Must not panic on nil slice.
	Zeroize(nil)
}
