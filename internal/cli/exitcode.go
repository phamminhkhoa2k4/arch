package cli

import "errors"

// Exit codes for automation: 0 success, 1 attention needed, 2 error.
const (
	ExitOK        = 0
	ExitAttention = 1
	ExitError     = 2
)

// exitError carries a process exit code through cobra's error return.
type exitError struct {
	Code int
	Err  error
}

func (e *exitError) Error() string { return e.Err.Error() }
func (e *exitError) Unwrap() error { return e.Err }

// attention wraps err so Execute reports the "attention needed" exit
// code instead of the generic execution-error code.
func attention(err error) error {
	return &exitError{Code: ExitAttention, Err: err}
}

// exitCodeOf maps a command error to a process exit code.
func exitCodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitError
}
