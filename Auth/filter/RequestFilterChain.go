package filter

import "net/http"

// RequestFilterChain manages filter execution for a single request.
type RequestFilterChain struct {
	filters []AuthenticationFilter
	index   int
}

// DoFilter executes the filters one by one.
func (chain *RequestFilterChain) DoFilter(req *http.Request, res http.ResponseWriter) error {
	if chain.index < len(chain.filters) {
		filter := chain.filters[chain.index]
		chain.index++
		return filter.DoFilter(req, res, chain)
	}
	return nil
}
