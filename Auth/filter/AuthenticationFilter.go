package filter

import (
	"net/http"
)

// AuthenticationFilter interface for custom filters.
type AuthenticationFilter interface {
	DoFilter(req *http.Request, res http.ResponseWriter, chain FilterChain) error
}
