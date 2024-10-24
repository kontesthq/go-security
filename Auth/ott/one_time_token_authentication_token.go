package ott

import (
	"github.com/kontesthq/go-security/Auth"
)

type OneTimeTokenAuthenticationToken struct {
	user          Auth.UserDetails
	tokenValue    string
	authenticated bool
}

func (t *OneTimeTokenAuthenticationToken) GetCredentials() interface{} {
	return t.tokenValue
}

func (t *OneTimeTokenAuthenticationToken) GetDetails() interface{} {
	return t.tokenValue
}

func (t *OneTimeTokenAuthenticationToken) GetPrincipal() interface{} {
	return t.user
}

func (t *OneTimeTokenAuthenticationToken) SetAuthenticated(isAuthenticated bool) error {
	t.authenticated = isAuthenticated
	return nil
}

// NewOneTimeUnauthenticatedToken Constructor for unauthenticated token
func NewOneTimeUnauthenticatedToken(tokenValue string) *OneTimeTokenAuthenticationToken {
	return &OneTimeTokenAuthenticationToken{
		user:          nil,
		tokenValue:    tokenValue,
		authenticated: false,
	}
}

// NewOneTimeUnauthenticatedTokenWithUser Constructor for unauthenticated token with user
func NewOneTimeUnauthenticatedTokenWithUser(user Auth.UserDetails, tokenValue string) *OneTimeTokenAuthenticationToken {
	return &OneTimeTokenAuthenticationToken{
		user:          user,
		tokenValue:    tokenValue,
		authenticated: false,
	}
}

// NewOneTimeAuthenticatedToken Constructor for authenticated token
func NewOneTimeAuthenticatedToken(user Auth.UserDetails) *OneTimeTokenAuthenticationToken {
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
