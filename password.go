package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrIncorrectPassword is returned when passwords are not equivalent.
var ErrIncorrectPassword = errors.New("incorrect Password")

// ErrConfirmPasswordNotMatch is returned when confirm password doesn't match new password.
var ErrConfirmPasswordNotMatch = errors.New("confirm password doesn't match new password")

// ErrSamePassword is returned when new password is same as old password.
var ErrSamePassword = errors.New("new password cannot be the same as old password")

// ErrBlankPassword is returned when new password is blank.
var ErrBlankPassword = errors.New("new password cannot be blank")

// Compare compares passwords equivalent.
// If hashed is true, p1 must be a bcrypt hashed password.
func Compare(p1, p2 string, hashed bool) (bool, error) {
	if p1 == p2 && !hashed {
		return true, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(p1), []byte(p2)); err != nil {
		if !hashed && err == bcrypt.ErrHashTooShort {
			return false, nil
		}
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// Change vailds and compares passwords.
// If hashed is true, p1 must be a bcrypt hashed password.
// Return a bcrypt hashed password on success.
func Change(p1, p2, n1, n2 string, hashed bool) (string, error) {
	ok, err := Compare(p1, p2, hashed)
	switch {
	case err != nil:

	case !ok:
		err = ErrIncorrectPassword
	case n1 != n2:
		err = ErrConfirmPasswordNotMatch
	case n1 == p1:
		err = ErrSamePassword
	case n1 == "":
		err = ErrBlankPassword

	default:
		password, err := bcrypt.GenerateFromPassword([]byte(n1), bcrypt.MinCost)
		if err != nil {
			return "", err
		}

		return string(password), nil
	}

	return "", err
}
