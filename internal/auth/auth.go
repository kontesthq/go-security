package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthMethod interface {
	Authenticate(username, password string) (bool, error) // returns true if successful
	//RefreshToken(token string) (string, string, error)              // returns new JWT token and refresh token
	//ValidateToken(token string) (string, error)                     // validates JWT token
}
