package security

import (
	"context"
	"errors"
	"sync"
)

// GlobalSecurityContextKey is the key used to store the security context in a global context.
type GlobalSecurityContextKey struct{}

// GlobalSecurityContextHolderStrategy is a static, global field-based strategy for managing security contexts.
type GlobalSecurityContextHolderStrategy struct {
	mu            sync.Mutex
	globalContext SecurityContext
}

// NewGlobalSecurityContextHolderStrategy creates a new instance of GlobalSecurityContextHolderStrategy.
func NewGlobalSecurityContextHolderStrategy() *GlobalSecurityContextHolderStrategy {
	return &GlobalSecurityContextHolderStrategy{}
}

// ClearContext clears the global security context.
func (s *GlobalSecurityContextHolderStrategy) ClearSecurityContext(ctx context.Context) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.globalContext = nil
	return context.WithValue(ctx, GlobalSecurityContextKey{}, nil)
}

// GetContext retrieves the current global security context, creating one if it doesn't exist.
func (s *GlobalSecurityContextHolderStrategy) GetContext(ctx context.Context) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.globalContext != nil {
		return ctx
	}

	// Create and store a new empty context if none exists
	s.globalContext = s.CreateSecurityEmptyContext()
	return ctx
}

func (s *GlobalSecurityContextHolderStrategy) GetSecurityContext(ctx context.Context) *SecurityContext {
	newctx := s.GetContext(ctx)

	securityContext, ok := newctx.Value(GlobalSecurityContextKey{}).(SecurityContext)

	if !ok || securityContext == nil {
		panic("SecurityContext not found in the context")
	}

	return &securityContext
}

// SetContext sets the global security context.
func (s *GlobalSecurityContextHolderStrategy) SetSecurityContext(ctx context.Context, securityContext SecurityContext) (context.Context, error) {
	if securityContext == nil {
		return ctx, errors.New("only non-nil SecurityContext instances are permitted")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.globalContext = securityContext
	return context.WithValue(ctx, GlobalSecurityContextKey{}, securityContext), nil
}

// CreateEmptyContext creates a new empty security context.
func (s *GlobalSecurityContextHolderStrategy) CreateSecurityEmptyContext() SecurityContext {
	return &SecurityContextImpl{} // Return a new instance of your SecurityContext implementation.
}
