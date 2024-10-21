package error

import "fmt"

// RefreshTokenInvalidError is an error type representing an invalid refresh token.
type RefreshTokenInvalidError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *RefreshTokenInvalidError) Error() string {
	return fmt.Sprintf("Refresh token is invalid")
}
