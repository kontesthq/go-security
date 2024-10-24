package Auth

import (
	"net/http"
)

type RedirectStrategy interface {
	SendRedirect(request *http.Request, response http.ResponseWriter, url string) error
}
