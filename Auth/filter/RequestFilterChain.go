package filter

import (
	"context"
	"github.com/kontesthq/go-security/Auth/security"
	"net/http"
)

// RequestFilterChain manages filter execution for a single request.
type RequestFilterChain struct {
	filters []AuthenticationFilter
	index   int
}

// DoFilter executes the filters one by one.
func (chain *RequestFilterChain) DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter) error {
	newCtx := security.GetSecurityContextHolder().GetContext(ctx)

	if chain.index < len(chain.filters) {
		filter := chain.filters[chain.index]
		chain.index++
		err := filter.DoFilter(newCtx, req, res, chain)

		return err
	}
	return nil
}
