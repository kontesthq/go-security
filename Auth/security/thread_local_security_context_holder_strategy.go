package security

import (
	"context"
	"errors"
)

// ThreadLocalSecurityContextKey is the key used to store the security context in context.Context.
type ThreadLocalSecurityContextKey struct{}

// ThreadLocalSecurityContextHolderStrategy is a context-based strategy for managing security contexts.
type ThreadLocalSecurityContextHolderStrategy struct{}

// NewThreadLocalSecurityContextHolderStrategy creates a new instance of ThreadLocalSecurityContextHolderStrategy.
func NewThreadLocalSecurityContextHolderStrategy() *ThreadLocalSecurityContextHolderStrategy {
	return &ThreadLocalSecurityContextHolderStrategy{}
}

// ClearSecurityContext clears the security context from the provided context.
func (s *ThreadLocalSecurityContextHolderStrategy) ClearSecurityContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, ThreadLocalSecurityContextKey{}, nil)
}

// GetContext retrieves the current context from the provided context, creating one if it doesn't exist.
func (s *ThreadLocalSecurityContextHolderStrategy) GetContext(ctx context.Context) context.Context {
	if securityContext, ok := ctx.Value(ThreadLocalSecurityContextKey{}).(SecurityContext); ok && securityContext != nil {
		return ctx
	} else {
		// Create a new security context and set it in the context
		newEmptySecurityContext := s.CreateSecurityEmptyContext()

		ctxWithValue := context.WithValue(ctx, ThreadLocalSecurityContextKey{}, newEmptySecurityContext)

		return ctxWithValue
	}
}

// GetSecurityContext retrieves the SecurityContext from the provided context.
func (s *ThreadLocalSecurityContextHolderStrategy) GetSecurityContext(ctx context.Context) *SecurityContext {
	// Retrieve or create the context with the SecurityContext
	newctx := s.GetContext(ctx)

	// Use the correct key to retrieve the SecurityContext
	securityContext, ok := newctx.Value(ThreadLocalSecurityContextKey{}).(SecurityContext)
	if !ok || securityContext == nil {
		panic("SecurityContext not found in the context")
	}

	return &securityContext
}

// SetSecurityContext sets the security context in the provided context.
func (s *ThreadLocalSecurityContextHolderStrategy) SetSecurityContext(ctx context.Context, securityContext SecurityContext) (context.Context, error) {
	if securityContext == nil {
		return ctx, errors.New("only non-nil SecurityContext instances are permitted")
	}
	return context.WithValue(ctx, ThreadLocalSecurityContextKey{}, securityContext), nil
}

// CreateSecurityEmptyContext creates a new empty security context.
func (s *ThreadLocalSecurityContextHolderStrategy) CreateSecurityEmptyContext() SecurityContext {
	return &SecurityContextImpl{} // Return a new instance of your SecurityContext implementation.
}
