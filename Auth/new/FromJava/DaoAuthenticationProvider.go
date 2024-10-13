package FromJava

import (
	"errors"
	new2 "github.com/ayushs-2k4/go-security/Auth/new"
	"sync"
)

type DaoAuthenticationProvider struct {
	passwordEncoder             new2.PasswordEncoder
	userDetailsService          new2.UserDetailsService
	userDetailsPasswordService  UserDetailsPasswordService
	compromisedPasswordChecker  CompromisedPasswordChecker
	userNotFoundEncodedPassword string
	userNotFoundPassword        string
	mutex                       sync.Mutex
}

// NewDaoAuthenticationProvider initializes the DaoAuthenticationProvider
func NewDaoAuthenticationProvider(passwordEncoder new2.PasswordEncoder) *DaoAuthenticationProvider {
	if passwordEncoder == nil {
		panic("passwordEncoder cannot be nil")
	}
	return &DaoAuthenticationProvider{
		passwordEncoder:      passwordEncoder,
		userNotFoundPassword: "userNotFoundPassword",
	}
}

// AdditionalAuthenticationChecks checks additional authentication requirements
func (p *DaoAuthenticationProvider) AdditionalAuthenticationChecks(userDetails new2.UserDetails, presentedPassword string) error {
	if presentedPassword == "" {
		return errors.New("no credentials provided")
	}

	if !p.passwordEncoder.Matches(presentedPassword, userDetails.GetPassword()) {
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
func (p *DaoAuthenticationProvider) RetrieveUser(username string) (new2.UserDetails, error) {
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
func (p *DaoAuthenticationProvider) CreateSuccessAuthentication(principal interface{}, presentedPassword string, user new2.UserDetails) (interface{}, error) {
	isPasswordCompromised := false
	if p.compromisedPasswordChecker != nil {
		isPasswordCompromised = p.compromisedPasswordChecker.Check(presentedPassword).compromised
	}

	if isPasswordCompromised {
		return nil, errors.New("the provided password is compromised, please change your password")
	}

	upgradeEncoding := p.userDetailsPasswordService != nil && p.passwordEncoder.UpgradeEncoding(user.GetPassword())
	if upgradeEncoding {
		newPassword, _ := p.passwordEncoder.Encode(presentedPassword)
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
func (p *DaoAuthenticationProvider) SetUserDetailsService(userDetailsService new2.UserDetailsService) {
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

// Example implementation of a PasswordEncoder
type SimplePasswordEncoder struct{}

// Encode encodes the password
func (e *SimplePasswordEncoder) Encode(password string) string {
	// Implement encoding logic (e.g., hash the password)
	return password // For demonstration; replace with real hash function
}

// Matches checks if the raw password matches the encoded password
func (e *SimplePasswordEncoder) Matches(rawPassword, encodedPassword string) bool {
	return rawPassword == encodedPassword // Replace with real check
}

// UpgradeEncoding checks if the encoding needs to be upgraded
func (e *SimplePasswordEncoder) UpgradeEncoding(encodedPassword string) bool {
	// Implement logic to check if encoding needs upgrade
	return false // For demonstration
}
