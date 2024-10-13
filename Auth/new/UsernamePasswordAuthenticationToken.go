package new

import (
	"errors"
)

// UsernamePasswordAuthenticationToken represents an Authentication implementation for a username/password.
type UsernamePasswordAuthenticationToken struct {
	AbstractAuthenticationToken
	principal   interface{}
	credentials interface{}
}

// NewUsernamePasswordAuthenticationToken creates a new unauthenticated token with principal and credentials.
func NewUsernamePasswordAuthenticationToken(principal interface{}, credentials interface{}) *UsernamePasswordAuthenticationToken {
	return &UsernamePasswordAuthenticationToken{
		AbstractAuthenticationToken: *NewAbstractAuthenticationToken(nil),
		principal:                   principal,
		credentials:                 credentials,
	}
}

// NewAuthenticatedUsernamePasswordAuthenticationToken creates a new authenticated token with authorities.
func NewAuthenticatedUsernamePasswordAuthenticationToken(principal interface{}, credentials interface{}, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
	token := &UsernamePasswordAuthenticationToken{
		AbstractAuthenticationToken: *NewAbstractAuthenticationToken(authorities),
		principal:                   principal,
		credentials:                 credentials,
	}
	token.SetAuthenticated(true)
	return token
}

// Authenticated creates an authenticated UsernamePasswordAuthenticationToken.
func (u *UsernamePasswordAuthenticationToken) Authenticated(principal interface{}, credentials interface{}, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
	return NewAuthenticatedUsernamePasswordAuthenticationToken(principal, credentials, authorities)
}

// GetCredentials returns the credentials of the principal.
func (u *UsernamePasswordAuthenticationToken) GetCredentials() interface{} {
	return u.credentials
}

// GetPrincipal returns the identity of the principal.
func (u *UsernamePasswordAuthenticationToken) GetPrincipal() interface{} {
	return u.principal
}

// SetAuthenticated sets the authentication status.
func (u *UsernamePasswordAuthenticationToken) SetAuthenticated(isAuthenticated bool) error {
	if isAuthenticated {
		return errors.New("cannot set this token to trusted - use constructor that takes authorities instead")
	}
	u.AbstractAuthenticationToken.SetAuthenticated(false)
	return nil
}

// EraseCredentials clears the credentials to enhance security.
func (u *UsernamePasswordAuthenticationToken) EraseCredentials() {
	u.credentials = nil
	u.AbstractAuthenticationToken.EraseCredentials()
}
