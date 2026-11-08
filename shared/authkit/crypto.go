// Package authkit implements the administrator authentication shared by the
// License Manager and ISP NetControl consoles: Argon2id passwords, server-side
// sessions, forced TOTP enrolment, CSRF tokens and login lockout.
package authkit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// RandomToken returns n random bytes, base64url encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is used to store session IDs: a database leak does not reveal
// usable cookies.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword returns an encoded Argon2id hash.
func HashPassword(pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword compares pw to an encoded hash in constant time.
func CheckPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword enforces the minimum password policy.
func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 256 {
		return errors.New("password is too long")
	}
	return nil
}

// SecretBox encrypts small secrets (TOTP seeds, signing keys) at rest with
// AES-256-GCM under a master key that lives outside the database.
type SecretBox struct{ aead cipher.AEAD }

// NewSecretBox takes a base64-encoded 32-byte master key.
func NewSecretBox(masterKeyB64 string) (*SecretBox, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(masterKeyB64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes, base64 encoded (generate with: openssl rand -base64 32)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

// Seal encrypts plaintext; aad binds the ciphertext to its purpose.
func (s *SecretBox) Seal(plaintext []byte, aad string) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(aad))
}

// Open decrypts a value produced by Seal with the same aad.
func (s *SecretBox) Open(ciphertext []byte, aad string) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return s.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], []byte(aad))
}
