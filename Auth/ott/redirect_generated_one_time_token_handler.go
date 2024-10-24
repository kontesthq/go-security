package ott

import (
	"github.com/kontesthq/go-security/Auth"
	"net/http"
)

type RedirectGeneratedOneTimeTokenHandler struct {
	redirectStrategy Auth.RedirectStrategy
	redirectURL      string
}

func NewRedirectGeneratedOneTimeTokenHandler(redirectURL string) *RedirectGeneratedOneTimeTokenHandler {
	return &RedirectGeneratedOneTimeTokenHandler{
		redirectStrategy: Auth.NewDefaultRedirectStrategy(),
		redirectURL:      redirectURL,
	}
}

func (r RedirectGeneratedOneTimeTokenHandler) Handle(request *http.Request, response http.ResponseWriter, oneTimeToken OneTimeToken) error {
	return r.redirectStrategy.SendRedirect(request, response, r.redirectURL)
}
