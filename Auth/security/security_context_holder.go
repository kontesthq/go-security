package security

import (
	"context"
	"fmt"
	"sync"
)

type SecurityContextHolder struct {
	strategyName    string
	strategy        SecurityContextHolderStrategy
	initializeCount int
	mu              sync.Mutex
}

const (
	MODE_THREADLOCAL            = "MODE_THREADLOCAL"
	MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL"
	MODE_GLOBAL                 = "MODE_GLOBAL"
	MODE_PRE_INITIALIZED        = "MODE_PRE_INITIALIZED"
	SYSTEM_PROPERTY             = "security.strategy"
)

//var Holder = SecurityContextHolder{
//	strategyName: MODE_THREADLOCAL, // Default strategy
//}
//
//func GetSecurityContextHolder() *SecurityContextHolder {
//	return &Holder
//}
//
//func init() {
//	Holder.initialize()
//}

var holder *SecurityContextHolder
var once sync.Once

// GetSecurityContextHolder initializes and returns the singleton SecurityContextHolder instance
func GetSecurityContextHolder() *SecurityContextHolder {
	once.Do(func() {
		holder = &SecurityContextHolder{
			strategyName: MODE_THREADLOCAL, // Default strategy
		}
		holder.initialize()
	})
	return holder
}

func (h *SecurityContextHolder) initialize() {
	h.initializeStrategy()
	h.initializeCount++
}

func (h *SecurityContextHolder) initializeStrategy() {
	if h.strategyName == MODE_PRE_INITIALIZED && h.strategy == nil {
		panic("When using MODE_PRE_INITIALIZED, strategy must be set.")
	}

	if h.strategyName == "" {
		h.strategyName = MODE_THREADLOCAL
	}

	switch h.strategyName {
	case MODE_THREADLOCAL:
		h.strategy = NewThreadLocalSecurityContextHolderStrategy()
		return

	case MODE_INHERITABLETHREADLOCAL:
		h.strategy = NewInheritableThreadLocalSecurityContextHolderStrategy()
		return

	case MODE_GLOBAL:
		h.strategy = NewGlobalSecurityContextHolderStrategy()
		return
	}
}

func (h *SecurityContextHolder) ClearSecurityContext(ctx context.Context) context.Context {
	return h.strategy.ClearSecurityContext(ctx)
}

func (h *SecurityContextHolder) GetContext(ctx context.Context) context.Context {
	return h.strategy.GetContext(ctx)
}

func (h *SecurityContextHolder) GetSecurityContext(ctx context.Context) *SecurityContext {
	return h.strategy.GetSecurityContext(ctx)
}

func (h *SecurityContextHolder) SetSecurityContext(ctx context.Context, context SecurityContext) (context.Context, error) {
	return h.strategy.SetSecurityContext(ctx, context)
}

func (h *SecurityContextHolder) GetContextHolderStrategy() SecurityContextHolderStrategy {
	return h.strategy
}

func (h *SecurityContextHolder) SetStrategyName(strategyName string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.strategyName = strategyName
	h.initialize()
}

func (h *SecurityContextHolder) CreateSecurityEmptyContext() SecurityContext {
	return h.strategy.CreateSecurityEmptyContext()
}

func (h *SecurityContextHolder) GetInitializeCount() int {
	return h.initializeCount
}

func (h *SecurityContextHolder) String() string {
	return fmt.Sprintf("SecurityContextHolder[strategy='%T'; initializeCount=%d]", h.strategy, h.initializeCount)
}
