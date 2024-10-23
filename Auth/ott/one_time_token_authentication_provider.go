package ott

import (
	"github.com/kontesthq/go-security/Auth"
	error2 "github.com/kontesthq/go-security/Auth/ott/error"
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
		return false, "", &error2.InvalidOneTimeTokenError{}
	} else {
		user, err := o.getUserDetails(oneTimeToken.GetUsername())

		if err != nil {
			return false, "", err
		}

		return true, user.GetUsername(), nil
	}
}
