package filter

import (
	"context"
	"net/http"
	"regexp"
)

type FilterChainImpl struct {
	filters   []AuthenticationFilter
	index     int
	skipPaths []*regexp.Regexp
}

func NewFilterChainImpl(filters []AuthenticationFilter) *FilterChainImpl {
	filters = append(filters, NewAuthorizationFilter())
	return &FilterChainImpl{
		filters:   filters,
		index:     0,
		skipPaths: make([]*regexp.Regexp, 0),
	}
}

func (chain *FilterChainImpl) AddSkipPath(path string) error {
	regexPath, err := regexp.Compile(path)
	if err != nil {
		return err
	}
	chain.skipPaths = append(chain.skipPaths, regexPath)
	return nil
}

func (chain *FilterChainImpl) AddSkipPaths(paths ...string) error {
	for _, path := range paths {
		if err := chain.AddSkipPath(path); err != nil {
			return err
		}
	}
	return nil
}

func (chain *FilterChainImpl) DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter) error {
	// Check if the path should skip the entire filter chain
	for _, skipPath := range chain.skipPaths {
		if skipPath.MatchString(req.URL.Path) {
			return nil // Skip the entire chain
		}
	}

	// Create a new chain for the current request
	newChain := &RequestFilterChain{
		filters: chain.filters,
		index:   0,
	}

	// Start filtering
	return newChain.DoFilter(req.Context(), req, res)
}
