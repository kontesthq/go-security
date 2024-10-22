package security

import "context"

// SecurityContextHolderStrategy defines the methods for managing the SecurityContext.
type SecurityContextHolderStrategy interface {
	ClearSecurityContext(ctx context.Context) context.Context
	GetContext(ctx context.Context) context.Context
	GetSecurityContext(ctx context.Context) *SecurityContext
	SetSecurityContext(ctx context.Context, context SecurityContext) (context.Context, error)
	CreateSecurityEmptyContext() SecurityContext
}
