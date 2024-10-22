package filter

import (
	"context"
	"net/http"
)

// AuthenticationFilter interface for custom filters.
type AuthenticationFilter interface {
	DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter, chain FilterChain) error
}
