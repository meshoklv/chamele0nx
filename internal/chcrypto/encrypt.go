package chcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Errors returned by Encrypt and Decrypt.
var (
	// ErrCiphertextTooShort is returned when the input is smaller than the
	// GCM nonce, so it cannot contain a nonce and a tag at all.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	// ErrDecryptionFailed is returned when GCM authentication fails. It is
	// deliberately uniform: the caller must not be able to tell a corrupt
	// tag from a wrong key.
	ErrDecryptionFailed = errors.New("decryption failed")
	// ErrInvalidKeySize is returned when the key is not the 32 bytes that
	// AES-256-GCM requires.
	ErrInvalidKeySize = errors.New("invalid key size: must be 32 bytes")
)

// Encrypt encrypts plaintext with AES-256-GCM using the given key.
// Key must be exactly 32 bytes. Returns nonce + ciphertext.
//
// The caller owns the key and should zeroize it (chcrypto.Zeroize) when
// encryption operations are complete. This function does not zeroize
// the key because the caller may reuse it for additional operations.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext (nonce + ciphertext) with the given key.
// Key must be exactly 32 bytes.
//
// The caller owns the key and should zeroize it (chcrypto.Zeroize) when
// decryption operations are complete. This function does not zeroize
// the key because the caller may reuse it for additional operations.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
