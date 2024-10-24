package multi_ott_example

import (
	"github.com/kontesthq/go-security/Auth/ott"
	error2 "github.com/kontesthq/go-security/examples/multi_ott_example/error"
	"sync"
)

type LoginOneTimeToken struct {
	oneTimeTokenService ott.OneTimeTokenService
	once                sync.Once
}

// NewLoginOneTimeToken initializes and returns an instance of LoginOneTimeToken
func NewLoginOneTimeToken() *LoginOneTimeToken {
	return &LoginOneTimeToken{}
}

func (o *LoginOneTimeToken) initializeOneTimeTokenService() {
	o.oneTimeTokenService = ott.NewInMemoryOneTimeTokenService()
}

func (o *LoginOneTimeToken) GenerateToken(username string) (*ott.OneTimeTokenAuthenticationToken, error) {
	oneTimeService := *o.getOneTimeTokenService()

	user, err := getUserDetails(username)

	if err != nil {
		return nil, err
	}

	return ott.GenerateOneTimeToken(user, oneTimeService)
}

func (o *LoginOneTimeToken) DoAuthenticateForgotPassword(providedToken string) (string, error) {
	oneTimeToken := ott.NewOneTimeUnauthenticatedToken(providedToken)

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

func (o *LoginOneTimeToken) getOneTimeTokenService() *ott.OneTimeTokenService {
	o.once.Do(func() {
		o.initializeOneTimeTokenService()
	})

	return &o.oneTimeTokenService
}
