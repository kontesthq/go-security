package main

import (
	"fmt"
	FromJava2 "github.com/kontesthq/go-security/Auth/FromJava"
	"github.com/kontesthq/go-security/Auth/PasswordEncoder/bcrypt"
	error2 "github.com/kontesthq/go-security/Auth/error"
	"log"
)

// MyUserDetails2 struct implements UserDetails interface
type MyUserDetails2 struct {
	username              string
	password              string
	authorities           []FromJava2.GrantedAuthority
	accountNonExpired     bool
	accountNonLocked      bool
	credentialsNonExpired bool
	enabled               bool
}

// NewMyUserDetails is a constructor for MyUserDetails2
func NewMyUserDetails(username, password string, authorities []FromJava2.GrantedAuthority, accountNonExpired, accountNonLocked, credentialsNonExpired, enabled bool) *MyUserDetails2 {
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
func (u *MyUserDetails2) GetAuthorities() []FromJava2.GrantedAuthority {
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
func (m *MyUserDetailsService) LoadUserByUsername(username string) (FromJava2.UserDetails, error) {
	if username == "user@example.com" {
		// Creating a sample authority for the user
		authority := &FromJava2.SimpleGrantedAuthority{Authority: "ROLE_USER"}

		// Create and return a New MyUserDetails2 instance
		return NewMyUserDetails(username, "This is Password", []FromJava2.GrantedAuthority{authority}, true, true, true, true), nil
	}

	// Return an error if the username is not found
	return nil, &error2.UserNotFoundError{}
}

func main() {

	//userDetailsService := &MyUserDetailsService{}

	daoAuthenticationProvider := FromJava2.NewDaoAuthenticationProvider(bcrypt.NewBCryptPasswordEncoder(), nil, nil, nil)

	authenticationProviders := []FromJava2.AuthenticationProvider{
		daoAuthenticationProvider,
	}

	providerManager := FromJava2.NewProviderManager(authenticationProviders, nil)

	var username = "user@example.com"  // Replace with actual username
	var password = "securePassword123" // Replace with actual password

	// Creating a New unauthenticated token
	token := FromJava2.NewUsernamePasswordAuthenticationToken(username, password)

	result, err := providerManager.Authenticate(token)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
	} else {
		log.Printf("Authentication successful: %v", result)
	}

	fmt.Println(providerManager)

	fmt.Println("Hello")
}
