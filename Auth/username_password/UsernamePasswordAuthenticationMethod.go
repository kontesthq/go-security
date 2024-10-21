package username_password

import (
	"errors"
	"github.com/ayushs-2k4/go-security/Auth"
	"github.com/ayushs-2k4/go-security/Auth/PasswordEncoder"
	error2 "github.com/ayushs-2k4/go-security/Auth/error"
	"log"
)

var globalDelegatingPasswordEncoder PasswordEncoder.GlobalDelegatingPasswordEncoder

type UsernamePasswordAuthenticationMethod struct {
	Username                           string
	Password                           string
	DelegatingPasswordEncoder          *PasswordEncoder.DelegatingPasswordEncoder
	ShouldAutomaticallyUpgradePassword bool
	GetUserDetails                     func(username string) (Auth.UserDetails, error)
	ChangePasswordFunc                 func(username, newPassword string) error
}

func NewUsernamePasswordAuthenticationMethod(username, password string, delegatingPasswordEncoder *PasswordEncoder.DelegatingPasswordEncoder, shouldAutomaticallyUpgradePassword bool, getUserDetailsFunc func(username string) (Auth.UserDetails, error), changePasswordFunc func(username, newPassword string) error) *UsernamePasswordAuthenticationMethod {
	if delegatingPasswordEncoder == nil {
		delegatingPasswordEncoder = globalDelegatingPasswordEncoder.GetGlobalPasswordEncoder()
	}

	return &UsernamePasswordAuthenticationMethod{
		Username:                           username,
		Password:                           password,
		DelegatingPasswordEncoder:          delegatingPasswordEncoder,
		ShouldAutomaticallyUpgradePassword: shouldAutomaticallyUpgradePassword,
		GetUserDetails:                     getUserDetailsFunc,
		ChangePasswordFunc:                 changePasswordFunc,
	}
}

func (u *UsernamePasswordAuthenticationMethod) Authenticate() (bool, error) {
	inputUsername := u.Username
	inputPassword := u.Password

	// Call the custom authentication function
	if u.GetUserDetails != nil {
		user, err := u.GetUserDetails(inputUsername)

		if err != nil {
			return false, err
		}

		if user == nil {
			return false, &error2.UserNotFoundError{}
		}

		dbPassword := user.GetPassword() // prefixEncodedPassword

		// check if password matches
		if passwordMatches, err := u.DelegatingPasswordEncoder.Matches(inputPassword, dbPassword); err != nil || !passwordMatches {
			return false, &error2.IncorrectPasswordError{}
		}

		// Authentication is successful
		if u.ShouldAutomaticallyUpgradePassword {
			shouldUpgradeEncoding := u.DelegatingPasswordEncoder.UpgradeEncoding(dbPassword)

			if shouldUpgradeEncoding {
				passwordWithNewEncoding, err := u.DelegatingPasswordEncoder.Encode(inputPassword)

				if err != nil {
					log.Printf("Cannot upgrade encoding due to error: %s\n", err)
				} else {
					log.Printf("Upgrading encoding for user: %s\n", user.GetUsername())
					err := u.ChangePasswordFunc(user.GetUsername(), passwordWithNewEncoding)
					if err != nil {
						return true, &error2.ChangePasswordError{}
					}
				}
			}
		}

		return true, nil

	} else {
		return false, errors.New("no getUserDetails function provided")
	}
}
