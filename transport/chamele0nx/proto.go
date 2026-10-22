package chamele0nx

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// Frame types for the Chamele0nX tunnel protocol.
// Frames are length-prefixed: [2-byte type][4-byte length][payload].
const (
	// frameKeyExchange carries ECDH X25519 public key (32 bytes).
	frameKeyExchange uint16 = 0x0001
	// frameData carries encrypted VPN data (AES-256-GCM).
	frameData uint16 = 0x0002
	// framePing is a keepalive frame (empty or with timestamp).
	framePing uint16 = 0x0003
	// frameClose signals graceful tunnel shutdown.
	frameClose uint16 = 0x0004

	// frameHeaderSize is the fixed overhead per frame: type(2) + length(4).
	frameHeaderSize = 6
	// maxFramePayload limits frame size to prevent DoS.
	maxFramePayload = 64 * 1024
)

// Errors returned when reading or writing Chamele0nX protocol frames.
var (
	// ErrFrameTooLarge is returned when a frame's payload exceeds
	// maxFramePayload, the cap that keeps a hostile peer from forcing a
	// large allocation.
	ErrFrameTooLarge = errors.New("chamele0nx: frame payload exceeds maximum")
	// ErrInvalidFrame is returned when a frame header carries a type that
	// this protocol version does not define.
	ErrInvalidFrame = errors.New("chamele0nx: invalid frame type")
)

// Frame is a single Chamele0nX protocol frame.
type Frame struct {
	Type    uint16
	Payload []byte
}

// WriteFrame writes a length-prefixed frame to w as a single Write call.
// Wire format: [type:2][length:4][payload:N]
// Uses a single Write for atomicity — prevents interleaving with concurrent writers.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > maxFramePayload {
		return ErrFrameTooLarge
	}

	buf := make([]byte, frameHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint16(buf[0:2], f.Type)
	binary.BigEndian.PutUint32(buf[2:6], uint32(len(f.Payload)))
	copy(buf[frameHeaderSize:], f.Payload)

	_, err := w.Write(buf)
	return err
}

// keyExchangePadMin and keyExchangePadMax bound the random padding-frame
// payload appended to a key-exchange write. The whole record — the
// key-exchange frame plus the padding frame — stays below the shaping
// threshold (512) so it is always emitted as one TLS record, whatever
// value is drawn.
const (
	keyExchangePadMin = 64
	keyExchangePadMax = 400
)

// writeKeyExchangeFrame writes a key-exchange frame followed by a
// random-length padding frame, both in a single Write so they land in one
// TLS record.
//
// A bare key-exchange frame is a fixed 32-byte payload (38 bytes framed,
// ~69 bytes as a TLS record) at a fixed position at the very start of
// every session, in both directions — a size-and-position constant a
// passive observer matches without decrypting anything. Padding the
// record to a per-write random size in a small range removes that
// constant.
//
// The padding is an ordinary ping frame. Both peers' relay loops already
// read a ping and move on without acting on its contents, so the padding
// is silently consumed and, crucially, a peer that does not pad still
// interoperates: it simply sends the bare key-exchange frame, and the
// other side reads it exactly as before. The frame format is unchanged.
func writeKeyExchangeFrame(w io.Writer, pubKey []byte) error {
	if len(pubKey) > maxFramePayload {
		return ErrFrameTooLarge
	}

	padLen, err := cryptoRandRange(keyExchangePadMin, keyExchangePadMax)
	if err != nil {
		return err
	}

	buf := make([]byte, frameHeaderSize+len(pubKey)+frameHeaderSize+padLen)

	// Key-exchange frame.
	binary.BigEndian.PutUint16(buf[0:2], frameKeyExchange)
	binary.BigEndian.PutUint32(buf[2:6], uint32(len(pubKey)))
	copy(buf[frameHeaderSize:], pubKey)

	// Padding frame (a ping the peer reads and ignores).
	off := frameHeaderSize + len(pubKey)
	binary.BigEndian.PutUint16(buf[off:off+2], framePing)
	binary.BigEndian.PutUint32(buf[off+2:off+6], uint32(padLen))
	if _, err := rand.Read(buf[off+frameHeaderSize:]); err != nil {
		return err
	}

	_, err = w.Write(buf)
	return err
}

// ReadFrame reads a single frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}

	ftype := binary.BigEndian.Uint16(header[0:2])
	length := binary.BigEndian.Uint32(header[2:6])

	if length > maxFramePayload {
		return Frame{}, ErrFrameTooLarge
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}

	return Frame{Type: ftype, Payload: payload}, nil
}
