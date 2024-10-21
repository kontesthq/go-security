package multi_ott_example

import (
	"errors"
	"github.com/ayushs-2k4/go-security/Auth"
	"github.com/ayushs-2k4/go-security/Auth/ott"
	"github.com/ayushs-2k4/go-security/internal/testing"
	"log/slog"
)

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

func GenerateOneTimeToken(user Auth.UserDetails, tokenService ott.OneTimeTokenService) (*ott.OneTimeTokenAuthenticationToken, error) {
	// Create a new token request
	request, err := ott.NewGenerateOneTimeTokenRequest(user.GetUsername())
	if err != nil {
		slog.Error("Error generating token request", slog.String("error", err.Error()))
		return nil, err
	}

	// Generate the one-time token
	oneTime := tokenService.Generate(*request)

	// Associate the token with the user
	oneTimeToken := ott.NewUnauthenticatedTokenWithUser(user, oneTime.GetTokenValue())
	return oneTimeToken, nil
}
