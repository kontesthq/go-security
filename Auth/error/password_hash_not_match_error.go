package error

import "fmt"

// PasswordHashNotMatchError is an error type returned when a password hash does not match the expected value.
type PasswordHashNotMatchError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *PasswordHashNotMatchError) Error() string {
	return fmt.Sprintf("password hash does not match")
}
