package FromJava

import (
	"errors"
	"github.com/ayushs-2k4/go-security/Auth/FromJava/PasswordEncoder"
	"sync"
)

type DaoAuthenticationProvider struct {
	*AbstractUserDetailsAuthenticationProvider
	passwordEncoder             PasswordEncoder.PasswordEncoder
	userDetailsService          UserDetailsService
	userDetailsPasswordService  UserDetailsPasswordService
	compromisedPasswordChecker  CompromisedPasswordChecker
	userNotFoundEncodedPassword string
	userNotFoundPassword        string
	mutex                       sync.Mutex
}

// NewDaoAuthenticationProvider initializes the DaoAuthenticationProvider
func NewDaoAuthenticationProvider(passwordEncoder PasswordEncoder.PasswordEncoder, userDetailsService UserDetailsService, userDetailsPasswordService UserDetailsPasswordService, compromisedPasswordChecker CompromisedPasswordChecker) *DaoAuthenticationProvider {
	if passwordEncoder == nil {
		panic("passwordEncoder cannot be nil")
	}

	// Initialize the embedded abstract provider
	abstractProvider := NewAbstractUserDetailsAuthenticationProvider()

	return &DaoAuthenticationProvider{
		AbstractUserDetailsAuthenticationProvider: abstractProvider,
		passwordEncoder:            passwordEncoder,
		userDetailsService:         userDetailsService,
		userDetailsPasswordService: userDetailsPasswordService,
		compromisedPasswordChecker: compromisedPasswordChecker,
		userNotFoundPassword:       "userNotFoundPassword",
	}
}

// AdditionalAuthenticationChecks checks additional authentication requirements
func (p *DaoAuthenticationProvider) AdditionalAuthenticationChecks(userDetails UserDetails, presentedPassword string) error {
	if presentedPassword == "" {
		return errors.New("no credentials provided")
	}

	// Call the Matches method and handle the error
	match, err := p.passwordEncoder.Matches(presentedPassword, userDetails.GetPassword())
	if err != nil {
		// Handle potential error during password comparison
		return err
	}

	// If passwords don't match, return an error
	if !match {
		return errors.New("bad credentials")
	}
	return nil
}

// DoAfterPropertiesSet checks if UserDetailsService is set
func (p *DaoAuthenticationProvider) DoAfterPropertiesSet() error {
	if p.userDetailsService == nil {
		return errors.New("a UserDetailsService must be set")
	}
	return nil
}

// RetrieveUser loads the user by username
func (p *DaoAuthenticationProvider) RetrieveUser(username string) (UserDetails, error) {
	p.prepareTimingAttackProtection()

	loadedUser, err := p.userDetailsService.LoadUserByUsername(username)
	if err != nil {
		return nil, err
	}

	if loadedUser == nil {
		return nil, errors.New("UserDetailsService returned null")
	}
	return loadedUser, nil
}

// CreateSuccessAuthentication creates successful authentication result
func (p *DaoAuthenticationProvider) CreateSuccessAuthentication(principal string, presentedPassword string, user UserDetails) (interface{}, error) {
	isPasswordCompromised := false
	if p.compromisedPasswordChecker != nil {
		isPasswordCompromised = p.compromisedPasswordChecker.Check(presentedPassword).compromised
	}

	if isPasswordCompromised {
		return nil, errors.New("the provided password is compromised, please change your password")
	}

	// Handle both the boolean and the error returned by UpgradeEncoding
	upgradeEncoding, err := p.passwordEncoder.UpgradeEncoding(user.GetPassword())
	if err != nil {
		return nil, err // Handle the error
	}

	// Now check if the encoding should be upgraded and if userDetailsPasswordService is present
	if upgradeEncoding && p.userDetailsPasswordService != nil {
		newPassword, err := p.passwordEncoder.Encode(presentedPassword)
		if err != nil {
			return nil, err
		}
		user = p.userDetailsPasswordService.UpdatePassword(user, newPassword)
	}

	return principal, nil
}

// PrepareTimingAttackProtection prepares for timing attack protection
func (p *DaoAuthenticationProvider) prepareTimingAttackProtection() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.userNotFoundEncodedPassword == "" {
		p.userNotFoundEncodedPassword, _ = p.passwordEncoder.Encode(p.userNotFoundPassword)
	}
}

// MitigateAgainstTimingAttack mitigates timing attacks
func (p *DaoAuthenticationProvider) MitigateAgainstTimingAttack(presentedPassword string) {
	if presentedPassword != "" {
		p.passwordEncoder.Matches(presentedPassword, p.userNotFoundEncodedPassword)
	}
}

// SetUserDetailsService sets the UserDetailsService
func (p *DaoAuthenticationProvider) SetUserDetailsService(userDetailsService UserDetailsService) {
	p.userDetailsService = userDetailsService
}

// SetUserDetailsPasswordService sets the UserDetailsPasswordService
func (p *DaoAuthenticationProvider) SetUserDetailsPasswordService(userDetailsPasswordService UserDetailsPasswordService) {
	p.userDetailsPasswordService = userDetailsPasswordService
}

// SetCompromisedPasswordChecker sets the CompromisedPasswordChecker
func (p *DaoAuthenticationProvider) SetCompromisedPasswordChecker(compromisedPasswordChecker CompromisedPasswordChecker) {
	p.compromisedPasswordChecker = compromisedPasswordChecker
}

func (p *DaoAuthenticationProvider) Authenticate(authentication Authentication) (Authentication, *AuthenticationException) {
	return p.AbstractUserDetailsAuthenticationProvider.Authenticate(authentication)
}

func (p *DaoAuthenticationProvider) Supports(authType Authentication) bool {
	return p.AbstractUserDetailsAuthenticationProvider.Supports(authType)
}
