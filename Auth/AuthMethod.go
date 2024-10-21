package Auth

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthenticationProvider interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (bool, string, error) // (isAuthenticated, username, error)
}
