package main

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth/FromJava/PasswordEncoder"
	"log"
	"net/http"
)

var userDatabase = map[string]string{ // Mock user database
	"ayushs_2k4": "anjubanke",
}

// MyUserDetails interface defines methods to get user information.
type MyUserDetails interface {
	GetUsername() string
	GetPassword() string
}

type MyUserDetailsImpl struct {
	Username string
	Password string
}

func (m *MyUserDetailsImpl) GetUsername() string {
	return m.Username
}

func (m *MyUserDetailsImpl) GetPassword() string {
	return m.Password
}

func NewMyUserDetailsImpl(username, password string) *MyUserDetailsImpl {
	return &MyUserDetailsImpl{
		Username: username,
		Password: password,
	}
}

func getUserDetails(username string) (MyUserDetails, error) { // Return MyUserDetails interface
	// Check if the user exists in the mock user database
	if password, exists := userDatabase[username]; exists {
		// Assuming that the password is stored in the database with the encoding prefix
		return NewMyUserDetailsImpl(username, password), nil // Return user details
	}
	return nil, errors.New("user not found") // User doesn't exist
}

func changePassword(username, newPassword string) {
	if _, exists := userDatabase[username]; exists {
		userDatabase[username] = newPassword
		fmt.Printf("Password for user '%s' has been successfully updated.\n", username)
	} else {
		fmt.Printf("User '%s' not found, cannot change password.\n", username)
	}
}

func main() {
	username := "ayushs_2k4"
	password := "anjubanke"

	usernamePasswordAuthenticationMethod := NewUsernamePasswordAuthenticationMethod(username, password, nil, getUserDetails, changePassword)

	authenticated, err := usernamePasswordAuthenticationMethod.Authenticate(nil, nil)
	if err != nil || !authenticated {
		log.Fatalf("Authentication failed with error: %s", err)
		return
	}

	fmt.Println("Authentication is successful")

	fmt.Printf("FinalMap: %v\n", userDatabase)
}

type UsernamePasswordAuthenticationMethod struct {
	Username                  string
	Password                  string
	DelegatingPasswordEncoder *PasswordEncoder.DelegatingPasswordEncoder
	GetUserDetails            func(username string) (MyUserDetails, error)
	ChangePasswordFunc        func(username, newPassword string)
}

func NewUsernamePasswordAuthenticationMethod(username, password string, delegatingPasswordEncoder *PasswordEncoder.DelegatingPasswordEncoder, getUserDetailsFunc func(username string) (MyUserDetails, error), changePasswordFunc func(username, newPassword string)) *UsernamePasswordAuthenticationMethod {

	if delegatingPasswordEncoder == nil {
		idForEncode := "bcrypt"
		encoders := PasswordEncoder.GetPasswordEncoders()
		var err error
		delegatingPasswordEncoder, err = PasswordEncoder.NewDelegatingPasswordEncoder(idForEncode, encoders)
		if err != nil {
			log.Fatalf("Error creating DelegatingPasswordEncoder: %s", err)
		}
	}

	return &UsernamePasswordAuthenticationMethod{
		Username:                  username,
		Password:                  password,
		DelegatingPasswordEncoder: delegatingPasswordEncoder,
		GetUserDetails:            getUserDetailsFunc,
		ChangePasswordFunc:        changePasswordFunc,
	}
}

func (u *UsernamePasswordAuthenticationMethod) Authenticate(w http.ResponseWriter, r *http.Request) (bool, error) {
	inputUsername := u.Username
	inputPassword := u.Password

	// Call the custom authentication function
	if u.GetUserDetails != nil {
		user, err := u.GetUserDetails(inputUsername)

		if err != nil || user == nil {
			return false, err
		}

		dbPassword := user.GetPassword() // prefixEncodedPassword
		fmt.Println("dbPassword: " + dbPassword)

		// check if password matches
		if passwordMatches, err := u.DelegatingPasswordEncoder.Matches(inputPassword, dbPassword); err != nil || !passwordMatches {
			return false, errors.New("password is wrong")
		}

		// Authentication is successful
		shouldUpgradeEncoding := u.DelegatingPasswordEncoder.UpgradeEncoding(dbPassword)

		if shouldUpgradeEncoding {
			passwordWithNewEncoding, err := u.DelegatingPasswordEncoder.Encode(inputPassword)

			if err != nil {
				log.Printf("Cannot upgrade encoding due to error: %s\n", err)
			} else {
				log.Printf("Upgrading encoding for user: %s\n", user.GetUsername())
				u.ChangePasswordFunc(user.GetUsername(), passwordWithNewEncoding)
			}
		}

		return true, nil

	} else {
		return false, errors.New("no Authenticate function provided")
	}
}
