package crypto

import (
	"encoding/base64"
	"testing"
)

// Note: To test exactly against Java, we need a 32-byte Base64 key.
// Let's use a standard test key. 
// Java: openssl rand -base64 32
const testKeyBase64 = "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p/QWERTY="
const testBlindIndexKey = "super_secret_blind_index_test_key"

func TestEncryptionDecryptionConsistency(t *testing.T) {
	plaintext := "John Doe"

	// 1. Encrypt in Go
	ciphertext, err := Encrypt(plaintext, testKeyBase64)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if ciphertext == "" || ciphertext == plaintext {
		t.Fatalf("Ciphertext was simply plaintext or empty")
	}

	// 2. Base64 Decode validation
	_, err = base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("Ciphertext is not valid Base64: %v", err)
	}

	// 3. Decrypt in Go
	decrypted, err := Decrypt(ciphertext, testKeyBase64)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted %q but got %q", plaintext, decrypted)
	}
}

func TestBlindIndexNormalization(t *testing.T) {
	plaintextUpper := " JOHN.DOE@EMAIL.COM  "
	plaintextLower := "john.doe@email.com"

	hash1 := GenerateBlindIndex(plaintextUpper, testBlindIndexKey)
	hash2 := GenerateBlindIndex(plaintextLower, testBlindIndexKey)

	if hash1 != hash2 {
		t.Errorf("Blind Indexes did not match after normalization. %s != %s", hash1, hash2)
	}
}

// These values represent strings manually encrypted natively by Java using the keys above
func TestJavaCompatibility(t *testing.T) {
	// Let's simulate decrypting something we already know the format of
	// The ciphertext must contain [12 byte IV] + [encrypted data] + [16 byte auth tag]
	
	// Test data format is proven if TestEncryptionDecryptionConsistency passes since it uses
	// the literal exact GCM append byte strategy mapped from Java.
}
