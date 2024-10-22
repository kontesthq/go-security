package security

import (
	"context"
	"errors"
)

// InheritableSecurityContextKey is the key used to store the security context in context.Context.
type InheritableSecurityContextKey struct{}

// InheritableThreadLocalSecurityContextHolderStrategy is a context-based strategy for managing security contexts that can be inherited.
type InheritableThreadLocalSecurityContextHolderStrategy struct{}

// NewInheritableThreadLocalSecurityContextHolderStrategy creates a new instance of InheritableThreadLocalSecurityContextHolderStrategy.
func NewInheritableThreadLocalSecurityContextHolderStrategy() *InheritableThreadLocalSecurityContextHolderStrategy {
	return &InheritableThreadLocalSecurityContextHolderStrategy{}
}

// ClearContext clears the security context from the provided context.
func (s *InheritableThreadLocalSecurityContextHolderStrategy) ClearSecurityContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, InheritableSecurityContextKey{}, nil)
}

// GetContext retrieves the current security context from the provided context, creating one if it doesn't exist.
func (s *InheritableThreadLocalSecurityContextHolderStrategy) GetContext(ctx context.Context) context.Context {
	if securityContext, ok := ctx.Value(InheritableSecurityContextKey{}).(SecurityContext); ok && securityContext != nil {
		return ctx
	}
	return ctx
}

func (s *InheritableThreadLocalSecurityContextHolderStrategy) GetSecurityContext(ctx context.Context) *SecurityContext {
	newctx := s.GetContext(ctx)

	securityContext, ok := newctx.Value(InheritableSecurityContextKey{}).(SecurityContext)

	if !ok || securityContext == nil {
		panic("SecurityContext not found in the context")
	}

	return &securityContext
}

// SetContext sets the security context in the provided context.
func (s *InheritableThreadLocalSecurityContextHolderStrategy) SetSecurityContext(ctx context.Context, securityContext SecurityContext) (context.Context, error) {
	if securityContext == nil {
		return ctx, errors.New("only non-nil SecurityContext instances are permitted")
	}
	return context.WithValue(ctx, InheritableSecurityContextKey{}, securityContext), nil
}

// CreateEmptyContext creates a new empty security context.
func (s *InheritableThreadLocalSecurityContextHolderStrategy) CreateSecurityEmptyContext() SecurityContext {
	return &SecurityContextImpl{} // Return a new instance of your SecurityContext implementation.
}
