package FromJava

import (
	"errors"
	new2 "github.com/ayushs-2k4/go-security/Auth/new"
	"log"
	"os"
)

type AbstractUserDetailsAuthenticationProvider struct {
	HideUserNotFoundExceptions bool
	PreAuthenticationChecks    UserDetailsChecker
	PostAuthenticationChecks   UserDetailsChecker
}

// NewAbstractUserDetailsAuthenticationProvider initializes the provider
func NewAbstractUserDetailsAuthenticationProvider() *AbstractUserDetailsAuthenticationProvider {
	// Initialize logger
	logger := log.New(os.Stdout, "LOG: ", log.Lshortfile)

	// Prepare messages for user checks
	messages := map[string]string{
		"AbstractUserDetailsAuthenticationProvider.locked":             "User account is locked",
		"AbstractUserDetailsAuthenticationProvider.disabled":           "User is disabled",
		"AbstractUserDetailsAuthenticationProvider.expired":            "User account has expired",
		"AbstractUserDetailsAuthenticationProvider.credentialsExpired": "User credentials have expired",
	}

	return &AbstractUserDetailsAuthenticationProvider{
		HideUserNotFoundExceptions: true,
		PreAuthenticationChecks:    NewDefaultPreAuthenticationChecks(logger, messages),
		PostAuthenticationChecks:   NewDefaultPostAuthenticationChecks(logger, messages),
	}
}

// Authenticate performs authentication for the given Authentication
func (p *AbstractUserDetailsAuthenticationProvider) Authenticate(authentication new2.Authentication) (new2.Authentication, error) {
	username := p.DetermineUsername(authentication)

	user, err := p.RetrieveUser(username, authentication)
	if err != nil {
		var authenticationException *AuthenticationException
		if errors.As(err, &authenticationException) && !p.HideUserNotFoundExceptions {
			return nil, err
		}
		return nil, NewAuthenticationExceptionWithoutCause("Bad credentials")
	}
	if user == nil {
		return nil, errors.New("retrieveUser returned nil")
	}

	p.PreAuthenticationChecks.Check(user)

	if err := p.AdditionalAuthenticationChecks(user, authentication); err != nil {
		return nil, err
	}

	p.PostAuthenticationChecks.Check(user)

	principalToReturn := user
	return p.CreateSuccessAuthentication(principalToReturn, authentication, user), nil
}

// DetermineUsername extracts the username from the Authentication
func (p *AbstractUserDetailsAuthenticationProvider) DetermineUsername(authentication new2.Authentication) string {
	if authentication.GetPrincipal() == nil {
		return "NONE_PROVIDED"
	}

	// Assert that the principal is of type User to get the username
	if principal, ok := authentication.GetPrincipal().(Principal); ok {
		return principal.GetName()
	}

	// Return a fallback if principal doesn't implement the Principal interface
	return "UNKNOWN"
}

// CreateSuccessAuthentication creates a successful Authentication object
func (p *AbstractUserDetailsAuthenticationProvider) CreateSuccessAuthentication(principal interface{}, authentication new2.Authentication, user new2.UserDetails) new2.Authentication {
	// Ensure we return the original credentials the user supplied,
	// so subsequent attempts are successful even with encoded passwords.
	// Also ensure we return the original getDetails(), so that future
	// authentication events after cache expiry contain the details

	credentials := authentication.GetCredentials()

	authorities := authentication.GetAuthorities()

	authToken := (&new2.UsernamePasswordAuthenticationToken{}).Authenticated(principal, credentials, authorities)

	authToken.SetDetails(authentication.GetDetails())

	//p.logger.Debug("Authenticated user")

	return authToken
}

/*
RetrieveUser

Allows subclasses to actually retrieve the UserDetails from an
implementation-specific location, with the option of throwing an
AuthenticationException immediately if the presented credentials are
incorrect (this is especially useful if it is necessary to bind to a resource as
the user in order to obtain or generate a UserDetails).

Subclasses are not required to perform any caching, as the
AbstractUserDetailsAuthenticationProvider will by default cache the
UserDetails. The caching of UserDetails does present additional complexity as this means
subsequent requests that rely on the cache will need to still have their credentials validated,
even if the correctness of credentials was assured by subclasses adopting a binding-based strategy
in this method. Accordingly, it is important that subclasses either disable caching (if they
want to ensure that this method is the only method that is capable of authenticating a request,
as no UserDetails will ever be cached) or ensure subclasses implement
additionalAuthenticationChecks(UserDetails, UsernamePasswordAuthenticationToken)
to compare the credentials of a cached UserDetails with subsequent
authentication requests.

Most of the time, subclasses will not perform credentials inspection in this method,
instead performing it in additionalAuthenticationChecks(UserDetails, UsernamePasswordAuthenticationToken)
so that code related to credentials validation need not be duplicated across two
methods.

Parameters:
- username: The username to retrieve.
- authentication: The authentication request, which subclasses may need to perform a binding-based retrieval of the UserDetails.

Returns:
- the user information (never nil - instead, an exception should be thrown).

Throws:
  - AuthenticationException if the credentials could not be validated
    (generally a BadCredentialsException, an AuthenticationServiceException, or
    UsernameNotFoundException).
*/
func (p *AbstractUserDetailsAuthenticationProvider) RetrieveUser(username string, authentication new2.Authentication) (new2.UserDetails, error) {
	return nil, errors.New("not implemented")
}

// SetHideUserNotFoundExceptions sets the hide user not found exceptions flag
func (p *AbstractUserDetailsAuthenticationProvider) SetHideUserNotFoundExceptions(hideUserNotFound bool) {
	p.HideUserNotFoundExceptions = hideUserNotFound
}

// AdditionalAuthenticationChecks should be implemented by subclasses
func (p *AbstractUserDetailsAuthenticationProvider) AdditionalAuthenticationChecks(userDetails new2.UserDetails, authentication new2.Authentication) error {
	return nil
}

// DefaultPreAuthenticationChecks for pre-authentication checks
type DefaultPreAuthenticationChecks struct {
	logger   *log.Logger
	messages map[string]string
}

// NewDefaultPreAuthenticationChecks creates a new instance of DefaultPreAuthenticationChecks
func NewDefaultPreAuthenticationChecks(logger *log.Logger, messages map[string]string) *DefaultPreAuthenticationChecks {
	return &DefaultPreAuthenticationChecks{logger: logger, messages: messages}
}

// Check performs pre-authentication checks on the user
func (c *DefaultPreAuthenticationChecks) Check(toCheck new2.UserDetails) error {
	if !toCheck.IsAccountNonLocked() {
		c.logger.Println("Failed to authenticate since user account is locked")
		return errors.New(c.messages["AbstractUserDetailsAuthenticationProvider.locked"])
	}
	if !toCheck.IsEnabled() {
		c.logger.Println("Failed to authenticate since user account is disabled")
		return errors.New(c.messages["AbstractUserDetailsAuthenticationProvider.disabled"])
	}
	if !toCheck.IsAccountNonExpired() {
		c.logger.Println("Failed to authenticate since user account has expired")
		return errors.New(c.messages["AbstractUserDetailsAuthenticationProvider.expired"])
	}
	return nil
}

// DefaultPostAuthenticationChecks for post-authentication checks
type DefaultPostAuthenticationChecks struct {
	logger   *log.Logger
	messages map[string]string
}

// NewDefaultPostAuthenticationChecks creates a new instance of DefaultPostAuthenticationChecks
func NewDefaultPostAuthenticationChecks(logger *log.Logger, messages map[string]string) *DefaultPostAuthenticationChecks {
	return &DefaultPostAuthenticationChecks{logger: logger, messages: messages}
}

// Check performs post-authentication checks on the user
func (c *DefaultPostAuthenticationChecks) Check(toCheck new2.UserDetails) error {
	if !toCheck.IsCredentialsNonExpired() {
		c.logger.Println("Failed to authenticate since user account credentials have expired")
		return errors.New(c.messages["AbstractUserDetailsAuthenticationProvider.credentialsExpired"])
	}
	return nil
}
