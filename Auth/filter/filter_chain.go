package filter

import (
	"context"
	"net/http"
)

// FilterChain interface for chaining filters.
type FilterChain interface {
	DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter) error
}
