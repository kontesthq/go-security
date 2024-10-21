package ott

type OneTimeTokenService interface {
	Generate(request GenerateOneTimeTokenRequest) OneTimeToken

	Consume(authenticationToken OneTimeTokenAuthenticationToken) OneTimeToken
}
