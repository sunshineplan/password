package password

import (
	"errors"
	"fmt"
)

// ErrIncorrectPassword is returned when passwords are not equivalent.
var ErrIncorrectPassword = errors.New("incorrect password")

var _ error = incorrectPasswordError(0)

type incorrectPasswordError int

func (incorrectPasswordError) Is(target error) bool { return target == ErrIncorrectPassword }

func (i incorrectPasswordError) Error() string {
	return fmt.Sprintf("incorrect password (%d)", i)
}

// ErrMaxPasswordAttempts is returned when exceeded maximum password attempts.
var ErrMaxPasswordAttempts = errors.New("exceeded max password retry")

var _ error = maxPasswordAttemptsError(0)

type maxPasswordAttemptsError int

func (maxPasswordAttemptsError) Is(target error) bool { return target == ErrMaxPasswordAttempts }

func (i maxPasswordAttemptsError) Error() string {
	return fmt.Sprintf("exceeded maximum password attempts (%d)", i)
}
