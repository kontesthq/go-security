package ott

import (
	"github.com/kontesthq/go-security/Auth"
	"net/http"
)

type OneTimeTokenAuthenticationConverter struct {
}

func (o *OneTimeTokenAuthenticationConverter) Convert(request http.Request) Auth.Authentication {
	token := request.URL.Query().Get("token")
	if token == "" {
		return nil
	}

	return NewOneTimeUnauthenticatedToken(token)
}
