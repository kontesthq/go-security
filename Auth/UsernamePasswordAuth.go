package Auth

import (
	"github.com/ayushs-2k4/go-security/model"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type UsernamePasswordAuth struct {
	userStore model.UserStore
}

func NewPasswordAuth(userStore model.UserStore) *UsernamePasswordAuth {
	return &UsernamePasswordAuth{
		userStore: userStore,
	}
}

func (p *UsernamePasswordAuth) Authenticate(w http.ResponseWriter, r *http.Request) (bool, error) {
	// For simplicity, we use query params (use headers/body for actual cases).
	username := ObtainUsernameFromHeader(r)
	password := ObtainPasswordFromHeader(r)

	user, err := p.userStore.FindUserByUsername(username)

	if err != nil || user == nil {
		return false, err
	}

	// Password check (in a real scenario, you'd retrieve the hash from a DB)
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return false, ErrInvalidCredentials
	}

	return true, nil
}

func ObtainUsernameFromHeader(r *http.Request) string {
	return r.Header.Get("X-Username")
}

func ObtainPasswordFromHeader(r *http.Request) string {
	return r.Header.Get("X-Password")
}
