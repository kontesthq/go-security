package FromJava

import "fmt"

// AuthenticationException is a concrete type for authentication-related exceptions.
type AuthenticationException struct {
	msg   string
	cause error
}

// NewAuthenticationException constructs a New AuthenticationException with a message and a root cause.
func NewAuthenticationException(msg string, cause error) *AuthenticationException {
	return &AuthenticationException{
		msg:   msg,
		cause: cause,
	}
}

// NewAuthenticationExceptionWithoutCause constructs a New AuthenticationException with a message and no root cause.
func NewAuthenticationExceptionWithoutCause(msg string) *AuthenticationException {
	return &AuthenticationException{
		msg: msg,
	}
}

// Error implements the error interface for AuthenticationException.
func (e *AuthenticationException) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.msg, e.cause)
	}
	return e.msg
}
