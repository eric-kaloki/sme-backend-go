package argon2

import (
	"log"

	"github.com/alexedwards/argon2id"
)

// Match existing Java defaults if creating new hashes
var params = &argon2id.Params{
	Memory:      65536,
	Iterations:  3,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword creates an Argon2id hash from a plaintext string
func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// CheckPassword compares a plaintext password with an Argon2id hash
func CheckPassword(password, hash string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		log.Printf("Error checking password hash: %v", err)
		return false, err
	}
	return match, nil
}
