package filter

import (
	"context"
	"net/http"
)

// OncePerRequestFilter interface for custom filters.
type OncePerRequestFilter interface {
	DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter, chain FilterChain) error
}
