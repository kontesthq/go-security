package ott

import (
	"github.com/ayushs-2k4/go-security/Auth"
)

type OneTimeTokenAuthenticationToken struct {
	user          Auth.UserDetails
	tokenValue    string
	authenticated bool
}

// NewUnauthenticatedToken Constructor for unauthenticated token
func NewUnauthenticatedToken(tokenValue string) *OneTimeTokenAuthenticationToken {
	return &OneTimeTokenAuthenticationToken{
		user:          nil,
		tokenValue:    tokenValue,
		authenticated: false,
	}
}

// NewUnauthenticatedTokenWithUser Constructor for unauthenticated token with user
func NewUnauthenticatedTokenWithUser(user Auth.UserDetails, tokenValue string) *OneTimeTokenAuthenticationToken {
	return &OneTimeTokenAuthenticationToken{
		user:          user,
		tokenValue:    tokenValue,
		authenticated: false,
	}
}

// NewAuthenticatedToken Constructor for authenticated token
func NewAuthenticatedToken(user Auth.UserDetails) *OneTimeTokenAuthenticationToken {
	return &OneTimeTokenAuthenticationToken{
		user:          user,
		authenticated: true,
	}
}

// GetTokenValue Get the token value
func (t *OneTimeTokenAuthenticationToken) GetTokenValue() string {
	return t.tokenValue
}

// GetUser Get the associated user
func (t *OneTimeTokenAuthenticationToken) GetUser() Auth.UserDetails {
	return t.user
}

// IsAuthenticated Check if the token is authenticated
func (t *OneTimeTokenAuthenticationToken) IsAuthenticated() bool {
	return t.authenticated
}
