package password

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var std = New(24*time.Hour, 5, nil)

// Default returns the standard passworder used by the package-level functions.
func Default() *Passworder { return std }

func SetDuration(d time.Duration) { std.SetDuration(d) }
func SetMaxAttempts(n int)        { std.SetMaxAttempts(n) }
func SetKey(key *rsa.PrivateKey)  { std.SetKey(key) }

// IsMaxAttempts checks id exceeded maximum password attempts or not.
func IsMaxAttempts(id any) bool { return std.IsMaxAttempts(id) }

// Reset resets id's incorrect password count.
func Reset(id any) { std.Reset(id) }

// Compare compares passwords equivalent, id is used to record password attempts.
func Compare(id any, key string, password string) error {
	return std.Compare(id, key, password)
}

// CompareHashAndPassword compares passwords equivalent, id is used to record password attempts.
// hash must be a bcrypt hashed password.
func CompareHashAndPassword(id any, hash string, password string) error {
	return std.CompareHashAndPassword(id, hash, password)
}

// HashPassword returns the bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func DecryptPKCS1v15(priv *rsa.PrivateKey, ciphertext string) (string, error) {
	if priv == nil {
		return "", errors.New("no private key")
	}
	cipher, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plain, err := rsa.DecryptPKCS1v15(nil, priv, cipher)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
