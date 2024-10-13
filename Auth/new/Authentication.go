package new

import "errors"

// Authentication represents a token for an authentication request or for an authenticated principal.
type Authentication interface {
	// GetAuthorities returns the authorities granted to the principal.
	GetAuthorities() []GrantedAuthority

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

// AuthenticationManager handles the authentication process.
type AuthenticationManager struct {
	userDetailsService UserDetailsService
	passwordEncoder    PasswordEncoder
}

// NewAuthenticationManager creates a new AuthenticationManager.
func NewAuthenticationManager(userDetailsService UserDetailsService, passwordEncoder PasswordEncoder) *AuthenticationManager {
	return &AuthenticationManager{
		userDetailsService: userDetailsService,
		passwordEncoder:    passwordEncoder,
	}
}

// Authenticate authenticates the user based on username and password.
func (am *AuthenticationManager) Authenticate(username, password string) (bool, error) {
	user, err := am.userDetailsService.LoadUserByUsername(username)
	if err != nil {
		return false, err
	}

	if am.passwordEncoder.Matches(password, user.GetPassword()) {
		return true, nil
	}
	return false, errors.New("authentication failed")
}

// UserDetailsService handles user details.
type UserDetailsService interface {
	LoadUserByUsername(username string) (UserDetails, error)
}
