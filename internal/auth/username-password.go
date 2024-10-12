package auth

import (
	"go-security/model"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type UsernamePasswordAuth struct {
	jwtSecret   []byte
	tokenExpiry time.Duration
	userStore   model.UserStore
}

func NewPasswordAuth(authConfig AuthConfig, userStore model.UserStore) *UsernamePasswordAuth {
	return &UsernamePasswordAuth{
		jwtSecret:   []byte(authConfig.JwtSecret),
		tokenExpiry: authConfig.TokenExpiry,
		userStore:   userStore,
	}
}

func (p *UsernamePasswordAuth) Authenticate(username, password string) (bool, error) {
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
