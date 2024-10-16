package error

import "fmt"

// IncorrectPasswordError is an error type representing a wrong password error.
type IncorrectPasswordError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *IncorrectPasswordError) Error() string {
	return fmt.Sprintf("provided password is incorrect")
}
