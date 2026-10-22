package chcrypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("10.0.0.1:443,10.0.0.2:443,10.0.0.3:443")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted doesn't match: got %s", decrypted)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("encryption of empty failed: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("decryption of empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(decrypted))
	}
}

func TestEncryptRejectsShortKey(t *testing.T) {
	_, err := Encrypt(make([]byte, 16), []byte("test"))
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize for 16-byte key, got %v", err)
	}
}

func TestDecryptRejectsShortKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	ct, _ := Encrypt(key, []byte("test"))

	_, err := Decrypt(make([]byte, 16), ct)
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize for 16-byte key, got %v", err)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}

	ciphertext, _ := Encrypt(key1, []byte("secret"))

	_, err := Decrypt(key2, ciphertext)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	_, err := Decrypt(key, []byte("short"))
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestEncryptDifferentNonce(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same message")
	ct1, _ := Encrypt(key, plaintext)
	ct2, _ := Encrypt(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext should produce different ciphertexts")
	}
}
