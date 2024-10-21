package error

import "fmt"

// WrongOTTError is an error type that represents an error when the OTT is wrong.
type WrongOTTError struct {
}

// Error implements the error interface, returning a formatted error message.
func (e *WrongOTTError) Error() string {
	return fmt.Sprintf("wrong OTT")
}
