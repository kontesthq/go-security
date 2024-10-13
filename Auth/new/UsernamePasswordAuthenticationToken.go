package new

// UsernamePasswordAuthenticationToken represents an Authentication implementation for a username/password.
type UsernamePasswordAuthenticationToken struct {
	AbstractAuthenticationToken
	principal   interface{}
	credentials interface{}
}

// NewUsernamePasswordAuthenticationToken creates a new unauthenticated token with principal and credentials.
func NewUsernamePasswordAuthenticationToken(principal, credentials interface{}) *UsernamePasswordAuthenticationToken {
	return &UsernamePasswordAuthenticationToken{
		AbstractAuthenticationToken: *NewAbstractAuthenticationToken(nil),
		principal:                   principal,
		credentials:                 credentials,
	}
}

// NewAuthenticatedUsernamePasswordAuthenticationToken creates a new authenticated token with authorities.
func NewAuthenticatedUsernamePasswordAuthenticationToken(principal, credentials interface{}, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
	token := &UsernamePasswordAuthenticationToken{
		AbstractAuthenticationToken: *NewAbstractAuthenticationToken(authorities),
		principal:                   principal,
		credentials:                 credentials,
	}
	token.SetAuthenticated(true)
	return token
}

// GetCredentials returns the credentials of the principal.
func (u *UsernamePasswordAuthenticationToken) GetCredentials() interface{} {
	return u.credentials
}

// GetPrincipal returns the identity of the principal.
func (u *UsernamePasswordAuthenticationToken) GetPrincipal() interface{} {
	return u.principal
}
