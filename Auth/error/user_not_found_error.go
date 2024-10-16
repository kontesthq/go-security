package error

import "fmt"

// UserNotFoundError is an error type representing a user not found error.
type UserNotFoundError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *UserNotFoundError) Error() string {
	return fmt.Sprintf("User not found")
}
