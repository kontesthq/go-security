package error

import "fmt"

// ChangePasswordError represents an error when an error occurs while changing the password.
type ChangePasswordError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *ChangePasswordError) Error() string {
	return fmt.Sprintf("An error occurred while changing the password")
}
