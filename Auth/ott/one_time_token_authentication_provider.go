package ott

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth"
	"log/slog"
	"os"
)

type OneTimeTokenAuthenticationMethod struct {
	oneTimeTokenAuthenticationToken OneTimeTokenAuthenticationToken
	oneTimeTokenService             OneTimeTokenService
	getUserDetails                  func(username string) (Auth.UserDetails, error)
}

func NewOneTimeTokenAuthenticationMethod(oneTimeTokenAuthenticationToken OneTimeTokenAuthenticationToken, oneTimeTokenService OneTimeTokenService, getUserDetailsFunc func(username string) (Auth.UserDetails, error)) *OneTimeTokenAuthenticationMethod {
	if oneTimeTokenService == nil {
		slog.Error("oneTimeTokenService cannot be nil")
		os.Exit(1)
	}

	if getUserDetailsFunc == nil {
		slog.Error("getUserDetailsFunc cannot be nil")
		os.Exit(1)
	}

	return &OneTimeTokenAuthenticationMethod{
		oneTimeTokenAuthenticationToken: oneTimeTokenAuthenticationToken,
		oneTimeTokenService:             oneTimeTokenService,
		getUserDetails:                  getUserDetailsFunc,
	}
}

func (o *OneTimeTokenAuthenticationMethod) Authenticate() (bool, string, error) {
	oneTimeToken := o.oneTimeTokenService.Consume(o.oneTimeTokenAuthenticationToken)

	if oneTimeToken == nil {
		return false, "", errors.New("invalid token")
	} else {
		user, err := o.getUserDetails(oneTimeToken.GetUsername())

		if err != nil {
			return false, "", err
		}

		var authenticated *OneTimeTokenAuthenticationToken
		authenticated = NewAuthenticatedToken(user)

		fmt.Println(authenticated)

		return true, user.GetUsername(), nil
	}
}
