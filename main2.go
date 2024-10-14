package main

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava/PasswordEncoder/bcrypt"
	"log"
)

// MyUserDetails2 struct implements UserDetails interface
type MyUserDetails2 struct {
	username              string
	password              string
	authorities           []FromJava.GrantedAuthority
	accountNonExpired     bool
	accountNonLocked      bool
	credentialsNonExpired bool
	enabled               bool
}

// NewMyUserDetails is a constructor for MyUserDetails2
func NewMyUserDetails(username, password string, authorities []FromJava.GrantedAuthority, accountNonExpired, accountNonLocked, credentialsNonExpired, enabled bool) *MyUserDetails2 {
	return &MyUserDetails2{
		username:              username,
		password:              password,
		authorities:           authorities,
		accountNonExpired:     accountNonExpired,
		accountNonLocked:      accountNonLocked,
		credentialsNonExpired: credentialsNonExpired,
		enabled:               enabled,
	}
}

// GetAuthorities returns the authorities granted to the user
func (u *MyUserDetails2) GetAuthorities() []FromJava.GrantedAuthority {
	return u.authorities
}

// GetPassword returns the password of the user
func (u *MyUserDetails2) GetPassword() string {
	return u.password
}

// GetUsername returns the username of the user
func (u *MyUserDetails2) GetUsername() string {
	return u.username
}

// IsAccountNonExpired indicates whether the user's account is expired
func (u *MyUserDetails2) IsAccountNonExpired() bool {
	return u.accountNonExpired
}

// IsAccountNonLocked indicates whether the user's account is locked
func (u *MyUserDetails2) IsAccountNonLocked() bool {
	return u.accountNonLocked
}

// IsCredentialsNonExpired indicates whether the user's credentials are expired
func (u *MyUserDetails2) IsCredentialsNonExpired() bool {
	return u.credentialsNonExpired
}

// IsEnabled indicates whether the user is enabled
func (u *MyUserDetails2) IsEnabled() bool {
	return u.enabled
}

type MyUserDetailsService struct {
}

// LoadUserByUsername loads user details by username
func (m *MyUserDetailsService) LoadUserByUsername(username string) (FromJava.UserDetails, error) {
	if username == "user@example.com" {
		// Creating a sample authority for the user
		authority := &FromJava.SimpleGrantedAuthority{Authority: "ROLE_USER"}

		// Create and return a new MyUserDetails2 instance
		return NewMyUserDetails(username, "This is Password", []FromJava.GrantedAuthority{authority}, true, true, true, true), nil
	}

	// Return an error if the username is not found
	return nil, errors.New("user not found")
}

func main() {

	//userDetailsService := &MyUserDetailsService{}

	daoAuthenticationProvider := FromJava.NewDaoAuthenticationProvider(bcrypt.NewBCryptPasswordEncoder(), nil, nil, nil)

	authenticationProviders := []FromJava.AuthenticationProvider{
		daoAuthenticationProvider,
	}

	providerManager := FromJava.NewProviderManager(authenticationProviders, nil)

	var username = "user@example.com"  // Replace with actual username
	var password = "securePassword123" // Replace with actual password

	// Creating a new unauthenticated token
	token := FromJava.NewUsernamePasswordAuthenticationToken(username, password)

	result, err := providerManager.Authenticate(token)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
	} else {
		log.Printf("Authentication successful: %v", result)
	}

	fmt.Println(providerManager)

	fmt.Println("Hello")
}
