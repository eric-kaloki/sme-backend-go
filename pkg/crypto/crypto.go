package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

var (
	ErrInvalidBase64      = errors.New("invalid base64 ciphertext")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrDecryptionFailed   = errors.New("decryption failed or invalid key")
)

const (
	gcmStandardNonceSize = 12
)

func parseKey(keyStr string) []byte {
	b, err := base64.StdEncoding.DecodeString(keyStr)
	if err == nil {
		switch len(b) {
		case 16, 24, 32:
			// Valid AES key sizes: use as-is
			return b
		case 64:
			// Java may use a 512-bit (64-byte) key; truncate to first 32 bytes for AES-256
			return b[:32]
		default:
			if len(b) > 32 {
				// Any key longer than 32 bytes: use first 32 bytes
				return b[:32]
			}
		}
	}
	panic("ENCRYPTION_SECRET_KEY is misconfigured or invalid Base64. Server cannot start securely.")
}

// Encrypt encrypts the plaintext using AES-256-GCM.
// The output format matches Java's EncryptionUtil:
// Base64([12-byte IV][Ciphertext + 16-byte Tag])
func Encrypt(plaintext string, keyBase64 string) (string, error) {
	if plaintext == "" {
		return plaintext, nil
	}

	key := parseKey(keyBase64)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcmStandardNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends the ciphertext and tag to the nonce.
	// Go's Seal natively computes: append(dst, ciphertext...)
	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Combine to match Java: [IV...] + [Ciphertext + Tag...]
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// Decrypt decrypts ciphertext previously created by Java's EncryptionUtil or Go's Encrypt.
func Decrypt(ciphertextBase64 string, keyBase64 string) (string, error) {
	if ciphertextBase64 == "" {
		return ciphertextBase64, nil
	}

	key := parseKey(keyBase64)

	combined, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", ErrInvalidBase64
	}

	if len(combined) < gcmStandardNonceSize {
		return "", ErrCiphertextTooShort
	}

	nonce, ciphertext := combined[:gcmStandardNonceSize], combined[gcmStandardNonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintextBytes, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintextBytes), nil
}

// GenerateBlindIndex creates a deterministic HMAC-SHA256 hash matching Java's BlindIndexGenerator.
// It trims and lowercases the input before hashing.
func GenerateBlindIndex(plaintext string, rawKey string) string {
	if plaintext == "" {
		return plaintext
	}

	normalized := strings.TrimSpace(strings.ToLower(plaintext))

	mac := hmac.New(sha256.New, []byte(rawKey))
	mac.Write([]byte(normalized))
	hash := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(hash)
}
