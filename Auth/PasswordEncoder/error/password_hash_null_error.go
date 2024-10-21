package error

import "fmt"

// PasswordHashNullError is an error type for when the password hash is null.
type PasswordHashNullError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *PasswordHashNullError) Error() string {
	return fmt.Sprintf("password hash is null")
}
