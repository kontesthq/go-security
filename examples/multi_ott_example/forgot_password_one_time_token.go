package multi_ott_example

import (
	"github.com/kontesthq/go-security/Auth/ott"
	error2 "github.com/kontesthq/go-security/examples/multi_ott_example/error"
	"sync"
)

type ForgotPasswordOneTimeToken struct {
	oneTimeTokenService ott.OneTimeTokenService
	once                sync.Once
}

// NewForgotPasswordOneTimeToken initializes and returns an instance of ForgotPasswordOneTimeToken
func NewForgotPasswordOneTimeToken() *ForgotPasswordOneTimeToken {
	return &ForgotPasswordOneTimeToken{}
}

func (o *ForgotPasswordOneTimeToken) initializeOneTimeTokenService() {
	o.oneTimeTokenService = ott.NewInMemoryOneTimeTokenService()
}

func (o *ForgotPasswordOneTimeToken) GenerateToken(username string) (*ott.OneTimeTokenAuthenticationToken, error) {
	oneTimeService := *o.getOneTimeTokenService()

	user, err := getUserDetails(username)

	if err != nil {
		return nil, err
	}

	return ott.GenerateOneTimeToken(user, oneTimeService)
}

func (o *ForgotPasswordOneTimeToken) DoAuthenticateForgotPassword(providedToken string) (string, error) {
	oneTimeToken := ott.NewUnauthenticatedToken(providedToken)

	oneTimeTokenService := *o.getOneTimeTokenService()

	oneTimeTokenAuthenticationMethod := ott.NewOneTimeTokenAuthenticationMethod(*oneTimeToken, oneTimeTokenService, getUserDetails)

	authenticated, username, err := oneTimeTokenAuthenticationMethod.Authenticate()
	if err != nil {
		return "", err
	}

	if !authenticated {
		return "", &error2.WrongOTTError{}
	}

	return username, nil
}

func (o *ForgotPasswordOneTimeToken) getOneTimeTokenService() *ott.OneTimeTokenService {
	o.once.Do(func() {
		o.initializeOneTimeTokenService()
	})

	return &o.oneTimeTokenService
}
