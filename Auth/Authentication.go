package Auth

// Authentication represents a token for an authentication request or for an authenticated principal.
type Authentication interface {
	// GetAuthorities returns the authorities granted to the principal.

	// GetCredentials returns the credentials that prove the identity of the principal.
	GetCredentials() interface{}

	// GetDetails returns additional details about the authentication request.
	GetDetails() interface{}

	// GetPrincipal returns the identity of the principal being authenticated.
	GetPrincipal() interface{}

	// IsAuthenticated checks whether the token has been authenticated.
	IsAuthenticated() bool

	// SetAuthenticated sets the authentication status of the token.
	SetAuthenticated(isAuthenticated bool) error
}
