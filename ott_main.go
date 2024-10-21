package main

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth"
	"github.com/ayushs-2k4/go-security/Auth/ott"
	"github.com/ayushs-2k4/go-security/internal/testing"
	"log/slog"
)

func main() {
	oneTimeTokenService := ott.NewInMemoryOneTimeTokenService()

	k, err := ott.NewGenerateOneTimeTokenRequest("testuser")

	if err != nil {
		slog.Error("Error generating token", slog.String("error", err.Error()))
		return
	}

	p := oneTimeTokenService.Generate(*k)

	fmt.Println("Token to give through email: ", p.GetTokenValue())

	oneTimeToken := *ott.NewUnauthenticatedTokenWithUser(userData["testuser"], p.GetTokenValue())

	DoAuthenticateOTT(oneTimeToken, oneTimeTokenService)
}

// Mock user data for demonstration
var userData = map[string]Auth.UserDetails{

	"testuser": &testing.TestUserPrincipal{User: testing.TestUser{
		Username: "testuser",
		Password: "password123", // Use a proper password (hashed) in a real app
		Leetcode: "testuserLeetcode",
	}},
}

func getUserDetails(username string) (Auth.UserDetails, error) {
	if user, exists := userData[username]; exists {
		return user, nil
	}

	return nil, errors.New("user not found")
}

func DoAuthenticateOTT(oneTimeToken ott.OneTimeTokenAuthenticationToken, oneTimeTokenService ott.OneTimeTokenService) {

	oneTimeTokenAuthenticationMethod := ott.NewOneTimeTokenAuthenticationMethod(oneTimeToken, oneTimeTokenService, getUserDetails)

	authenticated, err := oneTimeTokenAuthenticationMethod.Authenticate()
	if err != nil {
		slog.Error("Error authenticating", slog.String("error", err.Error()))
		return
	}

	if authenticated {
		slog.Info("Authenticated")
	} else {
		slog.Info("Not authenticated")
	}
}
