package ott

import (
	"github.com/ayushs-2k4/go-security/Auth"
)

func GenerateOneTimeToken(user Auth.UserDetails, tokenService OneTimeTokenService) (*OneTimeTokenAuthenticationToken, error) {
	// Create a new token request
	request, err := NewGenerateOneTimeTokenRequest(user.GetUsername())
	if err != nil {
		return nil, err
	}

	// Generate the one-time token
	oneTime := tokenService.Generate(*request)

	// Associate the token with the user
	oneTimeToken := NewUnauthenticatedTokenWithUser(user, oneTime.GetTokenValue())
	return oneTimeToken, nil
}
