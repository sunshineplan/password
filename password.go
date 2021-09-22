package password

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/sunshineplan/utils/cache"
	"golang.org/x/crypto/bcrypt"
)

var c = cache.New(true)
var maxAttempts = 5
var duration = 24 * time.Hour

func SetMaxAttempts(n int) {
	maxAttempts = n
}

func SetDuration(d time.Duration) {
	duration = d
}

// ErrIncorrectPassword is returned when passwords are not equivalent.
var ErrIncorrectPassword = errors.New("incorrect password")

type incorrectPasswordError struct{ n int }

func (e incorrectPasswordError) Is(target error) bool { return target == ErrIncorrectPassword }

func (e *incorrectPasswordError) Error() string {
	return fmt.Sprintf("incorrect password (%d)", e.n)
}

// ErrMaxPasswordAttempts is returned when exceeded maximum password attempts.
var ErrMaxPasswordAttempts = errors.New("exceeded max password retry")

type maxPasswordAttemptsError struct{}

func (e maxPasswordAttemptsError) Is(target error) bool { return target == ErrMaxPasswordAttempts }

func (e *maxPasswordAttemptsError) Error() string {
	return fmt.Sprintf("exceeded maximum password attempts (%d)", maxAttempts)
}

// ErrConfirmPasswordNotMatch is returned when confirm password doesn't match new password.
var ErrConfirmPasswordNotMatch = errors.New("confirm password doesn't match new password")

// ErrSamePassword is returned when new password is same as old password.
var ErrSamePassword = errors.New("new password cannot be the same as old password")

// ErrBlankPassword is returned when new password is blank.
var ErrBlankPassword = errors.New("new password cannot be blank")

// ErrNoPrivateKey is returned when new private key is nil.
var ErrNoPrivateKey = errors.New("no private key provided")

func recordIncorrectPassword(info string) error {
	var n int

	v, ok := c.Get(info)
	if !ok {
		n = 1
	} else {
		n = v.(int) + 1
	}
	c.Set(info, n, duration, nil)

	return &incorrectPasswordError{n}
}

// IsMaxAttempts checks info exceeded maximum password attempts or not.
func IsMaxAttempts(info string) bool {
	v, ok := c.Get(info)
	if !ok || v.(int) < maxAttempts {
		return false
	}

	return true
}

// Clear resets info's incorrect password count.
func Clear(info string) {
	c.Delete(info)
}

// GenerateFromPassword returns the bcrypt hash of the password.
func GenerateFromPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func compare(info, hashedPassword, password string, hashed bool, priv *rsa.PrivateKey) (string, bool, error) {
	if IsMaxAttempts(info) {
		return "", false, &maxPasswordAttemptsError{}
	}

	if priv != nil {
		ciphertext, err := base64.StdEncoding.DecodeString(password)
		if err != nil {
			return "", false, err
		}
		plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
		if err != nil {
			return "", false, err
		}
		password = string(plaintext)
	}
	if hashedPassword == password && !hashed {
		Clear(info)
		return password, true, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		if !hashed && err == bcrypt.ErrHashTooShort ||
			err == bcrypt.ErrMismatchedHashAndPassword {
			return "", false, recordIncorrectPassword(info)
		}
		return "", false, err
	}

	Clear(info)
	return password, true, nil
}

func change(info, hashedPassword, password, new1, new2 string, hashed bool, priv *rsa.PrivateKey) (string, error) {
	password, ok, err := compare(info, hashedPassword, password, hashed, priv)
	if ok {
		if priv != nil {
			ciphertext, err := base64.StdEncoding.DecodeString(new1)
			if err != nil {
				return "", err
			}
			plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
			if err != nil {
				return "", err
			}
			new1 = string(plaintext)

			ciphertext, err = base64.StdEncoding.DecodeString(new2)
			if err != nil {
				return "", err
			}
			plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
			if err != nil {
				return "", err
			}
			new2 = string(plaintext)
		}
		switch {
		case new1 != new2:
			err = ErrConfirmPasswordNotMatch
		case new1 == password:
			err = ErrSamePassword
		case new1 == "":
			err = ErrBlankPassword

		default:
			return GenerateFromPassword(new1)
		}
	}

	return "", err
}

// Compare compares passwords equivalent, info is used to record password attempts.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
func Compare(info, hashedPassword, password string, hashed bool) (ok bool, err error) {
	_, ok, err = compare(info, hashedPassword, password, hashed, nil)
	return
}

// Change vailds and compares passwords, info is used to record password attempts.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
// Return a bcrypt hashed password on success.
func Change(info, hashedPassword, password, new1, new2 string, hashed bool) (string, error) {
	return change(info, hashedPassword, password, new1, new2, hashed, nil)
}

// CompareRSA compares passwords equivalent, info is used to record password attempts,
// password must be a base64 encoded string using RSA.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
func CompareRSA(info, hashedPassword, password string, hashed bool, priv *rsa.PrivateKey) (ok bool, err error) {
	if priv == nil {
		return false, ErrNoPrivateKey
	}
	_, ok, err = compare(info, hashedPassword, password, hashed, priv)
	return
}

// ChangeRSA vailds and compares passwords, info is used to record password attempts,
// password, new1, new2 must be a base64 encoded string using RSA.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
// Return a bcrypt hashed password on success.
func ChangeRSA(info, hashedPassword, password, new1, new2 string, hashed bool, priv *rsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", ErrNoPrivateKey
	}
	return change(info, hashedPassword, password, new1, new2, hashed, priv)
}
