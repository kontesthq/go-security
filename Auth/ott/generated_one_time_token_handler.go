package ott

import "net/http"

type GeneratedOneTimeTokenHandler interface {
	Handle(request *http.Request, response http.ResponseWriter, oneTimeToken OneTimeToken) error
}
