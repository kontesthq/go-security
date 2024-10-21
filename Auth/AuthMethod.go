package Auth

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthMethod interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (bool, string, error) // (isAuthenticated, username, error)
}
