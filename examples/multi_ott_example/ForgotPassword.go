package multi_ott_example

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth"
	"github.com/ayushs-2k4/go-security/Auth/ott"
	"github.com/ayushs-2k4/go-security/internal/testing"
	"log/slog"
	"sync"
)

type OneTimeTokenForgotPassword struct {
	oneTimeTokenService ott.OneTimeTokenService
	once                sync.Once
}

// NewOneTimeTokenForgotPassword initializes and returns an instance of OneTimeTokenForgotPassword
func NewOneTimeTokenForgotPassword() *OneTimeTokenForgotPassword {
	return &OneTimeTokenForgotPassword{}
}

// Mock user data for demonstration
var userData = map[string]Auth.UserDetails{

	"testuser": &testing.TestUserPrincipal{User: testing.TestUser{
		Username: "testuser",
		Password: "password123", // Use a proper password (hashed) in a real app
		Leetcode: "testuserLeetcode",
	}},
}

func (o *OneTimeTokenForgotPassword) initializeOneTimeTokenService() {
	o.oneTimeTokenService = ott.NewInMemoryOneTimeTokenService()
}

func (o *OneTimeTokenForgotPassword) GenerateToken(username string) (*ott.OneTimeTokenAuthenticationToken, error) {
	user, err := getUserDetails(username)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Can not find user with username: %s", username))
	}

	request, err := ott.NewGenerateOneTimeTokenRequest(username)

	if err != nil {
		slog.Error("Error generating token", slog.String("error", err.Error()))
		return nil, err
	}

	oneTimeService := *o.getOneTimeTokenService()

	oneTime := oneTimeService.Generate(*request)

	oneTimeToken := ott.NewUnauthenticatedTokenWithUser(user, oneTime.GetTokenValue())

	return oneTimeToken, nil
}

func (o *OneTimeTokenForgotPassword) DoAuthenticateForgotPassword(providedToken string) (string, error) {
	oneTimeToken := ott.NewUnauthenticatedToken(providedToken)

	oneTimeTokenService := *o.getOneTimeTokenService()

	oneTimeTokenAuthenticationMethod := ott.NewOneTimeTokenAuthenticationMethod(*oneTimeToken, oneTimeTokenService, getUserDetails)

	authenticated, username, err := oneTimeTokenAuthenticationMethod.Authenticate()
	if err != nil {
		return "", err
	}

	if !authenticated {
		return "", errors.New("wrong OTT")
	}

	return username, nil
}

func (o *OneTimeTokenForgotPassword) getOneTimeTokenService() *ott.OneTimeTokenService {
	o.once.Do(func() {
		o.initializeOneTimeTokenService()
	})

	return &o.oneTimeTokenService
}

func getUserDetails(username string) (Auth.UserDetails, error) {
	if user, exists := userData[username]; exists {
		return user, nil
	}

	return nil, errors.New("user not found")
}
