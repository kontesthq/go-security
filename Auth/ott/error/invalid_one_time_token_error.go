package error

import "fmt"

// InvalidOneTimeTokenError is an error type that represents an invalid one time token error.
type InvalidOneTimeTokenError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *InvalidOneTimeTokenError) Error() string {
	return fmt.Sprintf("invalid one time token")
}
