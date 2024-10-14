package FromJava

import (
	"errors"
	"hash/fnv"
)

// UsernamePasswordAuthenticationToken represents an Authentication implementation for a username/password.
type UsernamePasswordAuthenticationToken struct {
	AbstractAuthenticationToken
	principal   string
	credentials interface{}
}

func (u *UsernamePasswordAuthenticationToken) Equals(another string) bool {
	return another == u.principal
}

func (u *UsernamePasswordAuthenticationToken) String() string {
	return u.GetName()
}

func (u *UsernamePasswordAuthenticationToken) HashCode() int {
	h := fnv.New32a()            // Create a new FNV-1a hash
	h.Write([]byte(u.GetName())) // Write the principal's name to the hash
	return int(h.Sum32())        // Return the hash as an int
}

func (u *UsernamePasswordAuthenticationToken) GetName() string {
	return u.principal
}

func (u *UsernamePasswordAuthenticationToken) Implies(subject Subject) bool {
	// Implement permission logic here based on roles or authorities
	// For simplicity, we return true or false based on a condition
	return true
}

// NewUsernamePasswordAuthenticationToken creates a new unauthenticated token with principal and credentials.
func NewUsernamePasswordAuthenticationToken(principal string, credentials interface{}) *UsernamePasswordAuthenticationToken {
	return &UsernamePasswordAuthenticationToken{
		AbstractAuthenticationToken: *NewAbstractAuthenticationToken(nil),
		principal:                   principal,
		credentials:                 credentials,
	}
}

// NewAuthenticatedUsernamePasswordAuthenticationToken creates a new authenticated token with authorities.
func NewAuthenticatedUsernamePasswordAuthenticationToken(principal string, credentials interface{}, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
	token := &UsernamePasswordAuthenticationToken{
		AbstractAuthenticationToken: *NewAbstractAuthenticationToken(authorities),
		principal:                   principal,
		credentials:                 credentials,
	}
	token.SetAuthenticated(true)
	return token
}

// Authenticated creates an authenticated UsernamePasswordAuthenticationToken.
func (u *UsernamePasswordAuthenticationToken) Authenticated(principal string, credentials interface{}, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
	return NewAuthenticatedUsernamePasswordAuthenticationToken(principal, credentials, authorities)
}

// GetCredentials returns the credentials of the principal.
func (u *UsernamePasswordAuthenticationToken) GetCredentials() interface{} {
	return u.credentials
}

// GetPrincipal returns the identity of the principal.
func (u *UsernamePasswordAuthenticationToken) GetPrincipal() string {
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
