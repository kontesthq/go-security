package Auth

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthMethod interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (bool, error) // returns true if successful
}
