package Auth

import "net/http"

type AuthenticationConverter interface {
	Convert(request http.Request) Authentication
}
