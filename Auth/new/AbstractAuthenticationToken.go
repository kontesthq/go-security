package new

import "errors"

// AbstractAuthenticationToken is a base implementation for Authentication objects.
type AbstractAuthenticationToken struct {
	authorities   []GrantedAuthority
	details       interface{}
	authenticated bool
}

// NewAbstractAuthenticationToken creates a new AbstractAuthenticationToken.
func NewAbstractAuthenticationToken(authorities []GrantedAuthority) *AbstractAuthenticationToken {
	return &AbstractAuthenticationToken{
		authorities: authorities,
	}
}

// GetAuthorities returns the authorities granted to the principal.
func (a *AbstractAuthenticationToken) GetAuthorities() []GrantedAuthority {
	return a.authorities
}

// GetDetails returns additional details about the authentication request.
func (a *AbstractAuthenticationToken) GetDetails() interface{} {
	return a.details
}

// SetDetails sets additional details about the authentication request.
func (a *AbstractAuthenticationToken) SetDetails(details interface{}) {
	a.details = details
}

// IsAuthenticated checks whether the token has been authenticated.
func (a *AbstractAuthenticationToken) IsAuthenticated() bool {
	return a.authenticated
}

// SetAuthenticated sets the authentication status of the token.
func (a *AbstractAuthenticationToken) SetAuthenticated(isAuthenticated bool) error {
	if !isAuthenticated {
		a.authenticated = false
		return nil
	}
	// Potential security risk: only set to true when authentication is trusted
	return errors.New("cannot set authenticated to true for this token")
}

// EraseCredentials erases the credentials (if any).
func (a *AbstractAuthenticationToken) EraseCredentials() {
	// Implement credential erasure logic here if required.
}
