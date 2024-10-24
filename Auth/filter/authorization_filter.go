package filter

import (
	"context"
	"errors"
	"github.com/kontesthq/go-security/Auth/security"
	"net/http"
)

type AuthorizationFilter struct {
}

// NewAuthorizationFilter creates a new instance of AuthorizationFilter with the given SecurityContextHolderStrategy.
func NewAuthorizationFilter() *AuthorizationFilter {
	return &AuthorizationFilter{}
}

func (a *AuthorizationFilter) DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter, chain FilterChain) error {

	// Retrieve the security context from the context
	securityContext := *security.GetSecurityContextHolder().GetSecurityContext(ctx)

	if securityContext == nil {
		return errors.New("security context is nil")
	}

	authentication := securityContext.GetAuthentication()

	// Check if the user is authenticated
	if authentication == nil || !authentication.IsAuthenticated() {
		// If not authenticated, respond with an unauthorized status
		return errors.New("unauthorized string")
	}

	// Proceed with the next filter in the chain
	return chain.DoFilter(ctx, req, res)
}
