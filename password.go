package password

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrIncorrectPassword is returned when passwords are not equivalent.
var ErrIncorrectPassword = errors.New("incorrect password")

// ErrConfirmPasswordNotMatch is returned when confirm password doesn't match new password.
var ErrConfirmPasswordNotMatch = errors.New("confirm password doesn't match new password")

// ErrSamePassword is returned when new password is same as old password.
var ErrSamePassword = errors.New("new password cannot be the same as old password")

// ErrBlankPassword is returned when new password is blank.
var ErrBlankPassword = errors.New("new password cannot be blank")

// ErrNoPrivateKey is returned when new private key is nil.
var ErrNoPrivateKey = errors.New("no private key provided")

// GenerateFromPassword returns the bcrypt hash of the password.
func GenerateFromPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func compare(hashedPassword, password string, hashed bool, priv *rsa.PrivateKey) (string, bool, error) {
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
		return password, true, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		if !hashed && err == bcrypt.ErrHashTooShort {
			return "", false, nil
		}
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return "", false, nil
		}
		return "", false, err
	}

	return password, true, nil
}

func change(hashedPassword, password, new1, new2 string, hashed bool, priv *rsa.PrivateKey) (string, error) {
	password, ok, err := compare(hashedPassword, password, hashed, priv)
	switch {
	case err != nil:

	case !ok:
		err = ErrIncorrectPassword
	case new1 != new2:
		err = ErrConfirmPasswordNotMatch
	case new1 == password:
		err = ErrSamePassword
	case new1 == "":
		err = ErrBlankPassword

	default:
		return GenerateFromPassword(new1)
	}

	return "", err
}

// Compare compares passwords equivalent.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
func Compare(hashedPassword, password string, hashed bool) (ok bool, err error) {
	_, ok, err = compare(hashedPassword, password, hashed, nil)
	return
}

// Change vailds and compares passwords.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
// Return a bcrypt hashed password on success.
func Change(hashedPassword, password, new1, new2 string, hashed bool) (string, error) {
	return change(hashedPassword, password, new1, new2, hashed, nil)
}

// CompareRSA compares passwords equivalent.
// password must be a base64 encoded string using RSA.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
func CompareRSA(hashedPassword, password string, hashed bool, priv *rsa.PrivateKey) (ok bool, err error) {
	if priv == nil {
		return false, ErrNoPrivateKey
	}
	_, ok, err = compare(hashedPassword, password, hashed, priv)
	return
}

// ChangeRSA vailds and compares passwords.
// password must be a base64 encoded string using RSA.
// If hashed is true, hashedPassword must be a bcrypt hashed password.
// Return a bcrypt hashed password on success.
func ChangeRSA(hashedPassword, password, new1, new2 string, hashed bool, priv *rsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", ErrNoPrivateKey
	}
	return change(hashedPassword, password, new1, new2, hashed, priv)
}
