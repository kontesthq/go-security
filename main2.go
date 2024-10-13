package main

import (
	"errors"
	"fmt"
	new2 "github.com/ayushs-2k4/go-security/Auth/new"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava/PasswordEncoder"
	"log"
)

// MyUserDetails struct implements UserDetails interface
type MyUserDetails struct {
	username              string
	password              string
	authorities           []new2.GrantedAuthority
	accountNonExpired     bool
	accountNonLocked      bool
	credentialsNonExpired bool
	enabled               bool
}

// NewMyUserDetails is a constructor for MyUserDetails
func NewMyUserDetails(username, password string, authorities []new2.GrantedAuthority, accountNonExpired, accountNonLocked, credentialsNonExpired, enabled bool) *MyUserDetails {
	return &MyUserDetails{
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
func (u *MyUserDetails) GetAuthorities() []new2.GrantedAuthority {
	return u.authorities
}

// GetPassword returns the password of the user
func (u *MyUserDetails) GetPassword() string {
	return u.password
}

// GetUsername returns the username of the user
func (u *MyUserDetails) GetUsername() string {
	return u.username
}

// IsAccountNonExpired indicates whether the user's account is expired
func (u *MyUserDetails) IsAccountNonExpired() bool {
	return u.accountNonExpired
}

// IsAccountNonLocked indicates whether the user's account is locked
func (u *MyUserDetails) IsAccountNonLocked() bool {
	return u.accountNonLocked
}

// IsCredentialsNonExpired indicates whether the user's credentials are expired
func (u *MyUserDetails) IsCredentialsNonExpired() bool {
	return u.credentialsNonExpired
}

// IsEnabled indicates whether the user is enabled
func (u *MyUserDetails) IsEnabled() bool {
	return u.enabled
}

type MyUserDetailsService struct {
}

// LoadUserByUsername loads user details by username
func (m *MyUserDetailsService) LoadUserByUsername(username string) (new2.UserDetails, error) {
	if username == "user@example.com" {
		// Creating a sample authority for the user
		authority := &new2.SimpleGrantedAuthority{Authority: "ROLE_USER"}

		// Create and return a new MyUserDetails instance
		return NewMyUserDetails(username, "This is Password", []new2.GrantedAuthority{authority}, true, true, true, true), nil
	}

	// Return an error if the username is not found
	return nil, errors.New("user not found")
}

func main() {

	userDetailsService := &MyUserDetailsService{}

	daoAuthenticationProvider := FromJava.NewDaoAuthenticationProvider(PasswordEncoder.NewBCryptPasswordEncoder(), userDetailsService, nil, nil)

	authenticationProviders := []FromJava.AuthenticationProvider{
		daoAuthenticationProvider,
	}

	providerManager := FromJava.NewProviderManager(authenticationProviders, nil)

	var username = "user@example.com"  // Replace with actual username
	var password = "securePassword123" // Replace with actual password

	// Creating a new unauthenticated token
	token := new2.NewUsernamePasswordAuthenticationToken(username, password)

	result, err := providerManager.Authenticate(token)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
	} else {
		log.Printf("Authentication successful: %v", result)
	}

	fmt.Println(providerManager)

	fmt.Println("Hello")
}
