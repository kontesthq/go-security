package filter

import (
	"net/http"
)

// FilterChain interface for chaining filters.
type FilterChain interface {
	DoFilter(req *http.Request, res http.ResponseWriter) error
}
