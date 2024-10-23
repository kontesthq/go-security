package username_password

import (
	"errors"
	"github.com/kontesthq/go-security/Auth"
	"github.com/kontesthq/go-security/Auth/PasswordEncoder"
	error2 "github.com/kontesthq/go-security/Auth/error"
	"log"
)

var globalDelegatingPasswordEncoder PasswordEncoder.GlobalDelegatingPasswordEncoder

type UsernamePasswordAuthenticationProvider struct {
	DelegatingPasswordEncoder          *PasswordEncoder.DelegatingPasswordEncoder
	ShouldAutomaticallyUpgradePassword bool
	GetUserDetails                     func(username string) (Auth.UserDetails, error)
	ChangePasswordFunc                 func(username, newPassword string) error
}

func NewUsernamePasswordAuthenticationProvider(delegatingPasswordEncoder *PasswordEncoder.DelegatingPasswordEncoder, shouldAutomaticallyUpgradePassword bool, getUserDetailsFunc func(username string) (Auth.UserDetails, error), changePasswordFunc func(username, newPassword string) error) *UsernamePasswordAuthenticationProvider {
	if delegatingPasswordEncoder == nil {
		delegatingPasswordEncoder = globalDelegatingPasswordEncoder.GetGlobalPasswordEncoder()
	}

	return &UsernamePasswordAuthenticationProvider{
		DelegatingPasswordEncoder:          delegatingPasswordEncoder,
		ShouldAutomaticallyUpgradePassword: shouldAutomaticallyUpgradePassword,
		GetUserDetails:                     getUserDetailsFunc,
		ChangePasswordFunc:                 changePasswordFunc,
	}
}

func (u *UsernamePasswordAuthenticationProvider) Authenticate(authentication Auth.Authentication) (Auth.Authentication, error) {
	usernamePasswordAuthenticationToken, ok := authentication.(*UsernamePasswordAuthenticationToken)

	if !ok {
		return nil, errors.New("invalid authentication token")
	}

	inputUsername := usernamePasswordAuthenticationToken.username
	inputPassword := usernamePasswordAuthenticationToken.password

	// Call the custom authentication function
	if u.GetUserDetails != nil {
		user, err := u.GetUserDetails(inputUsername)

		if err != nil {
			//return false, "", err
			return nil, err
		}

		if user == nil {
			//return false, "", &error2.UserNotFoundError{}
			return nil, &error2.UserNotFoundError{}
		}

		dbPassword := user.GetPassword() // prefixEncodedPassword

		// check if password matches
		if passwordMatches, err := u.DelegatingPasswordEncoder.Matches(inputPassword, dbPassword); err != nil || !passwordMatches {
			//return false, "", &error2.IncorrectPasswordError{}
			return nil, &error2.IncorrectPasswordError{}
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
						//return true, user.GetUsername(), &error2.ChangePasswordError{}
						return u.createSuccessAuthentication(user.GetUsername(), user.GetPassword()), &error2.ChangePasswordError{}
					}
				}
			}
		}

		//return true, user.GetUsername(), nil
		return u.createSuccessAuthentication(user.GetUsername(), user.GetPassword()), nil
	} else {
		//return false, "", errors.New("no getUserDetails function provided")
		return nil, errors.New("no getUserDetails function provided")
	}
}

func (u *UsernamePasswordAuthenticationProvider) createSuccessAuthentication(username, password string) Auth.Authentication {
	usernamePasswordAuthenticationToken := NewUsernamePasswordAuthenticationToken(username, password)

	err := usernamePasswordAuthenticationToken.SetAuthenticated(true)
	if err != nil {
		return nil
	}

	return usernamePasswordAuthenticationToken
}
