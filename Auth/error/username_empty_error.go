package error

import "fmt"

// UsernameEmptyError is an error type that is returned when the username is empty.
type UsernameEmptyError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *UsernameEmptyError) Error() string {
	return fmt.Sprintf("username cannot be empty")
}
