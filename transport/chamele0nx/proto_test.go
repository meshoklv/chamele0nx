package chamele0nx

import (
	"bytes"
	"testing"
)

// TestWriteKeyExchangeFramePads verifies the key-exchange masking: the
// key-exchange frame is written unchanged (same type, same 32-byte
// payload) but the record is padded to a per-write random size with a
// trailing ping frame, so the record length is no longer a fixed
// constant at the start of every session. The whole record stays below
// the shaping threshold so it is always a single TLS record. Before the
// change this wrote a bare 38-byte frame every time.
func TestWriteKeyExchangeFramePads(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	distinct := make(map[int]int)
	const n = 500
	for i := 0; i < n; i++ {
		var buf bytes.Buffer
		if err := writeKeyExchangeFrame(&buf, pub); err != nil {
			t.Fatalf("writeKeyExchangeFrame: %v", err)
		}

		total := buf.Len()
		distinct[total]++
		// Always one TLS record: must stay under the shaping threshold.
		if total >= minShapingThreshold {
			t.Fatalf("padded key-exchange record %d must stay below the shaping threshold %d", total, minShapingThreshold)
		}

		// First frame: the key exchange, byte-for-byte unchanged.
		ke, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read key-exchange frame: %v", err)
		}
		if ke.Type != frameKeyExchange {
			t.Fatalf("first frame type = %#x, want frameKeyExchange", ke.Type)
		}
		if !bytes.Equal(ke.Payload, pub) {
			t.Fatalf("key-exchange payload altered: got %x want %x", ke.Payload, pub)
		}

		// Second frame: the padding, a ping the peer ignores.
		pad, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read padding frame: %v", err)
		}
		if pad.Type != framePing {
			t.Fatalf("padding frame type = %#x, want framePing", pad.Type)
		}
		if buf.Len() != 0 {
			t.Fatalf("unexpected trailing bytes after key-exchange + padding: %d", buf.Len())
		}
	}

	if len(distinct) < 20 {
		t.Fatalf("padded record length barely varies: only %d distinct sizes across %d writes", len(distinct), n)
	}
}
