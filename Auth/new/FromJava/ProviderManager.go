package FromJava

import (
	"fmt"
	"log"
	"reflect"
)

type ProviderManager struct {
	eventPublisher            AuthenticationEventPublisher
	providers                 []AuthenticationProvider
	eraseCredentialsAfterAuth bool
	parent                    AuthenticationManager
}

func NewProviderManager(providers []AuthenticationProvider, parent AuthenticationManager) *ProviderManager {
	if providers == nil {
		log.Fatal("providers list cannot be null")
	}
	return &ProviderManager{
		eventPublisher:            &NullEventPublisher{},
		providers:                 providers,
		eraseCredentialsAfterAuth: true,
		parent:                    parent,
	}
}

func (pm *ProviderManager) Authenticate(authentication Authentication) (Authentication, error) {
	var lastException *AuthenticationException
	var parentException *AuthenticationException
	var result Authentication
	var parentResult Authentication

	currentPosition := 0
	size := len(pm.providers)

	for _, provider := range pm.providers {
		if !provider.Supports(authentication) {
			continue
		}
		log.Printf("Authenticating request with %s (%d/%d)", fmt.Sprintf("%T", provider), currentPosition+1, size)

		result, err := provider.Authenticate(authentication)
		if err != nil {
			lastException = err
			continue
		}
		if result != nil {
			pm.copyDetails(authentication, result)
			break
		}
		currentPosition++
	}

	if result == nil && pm.parent != nil {
		// Allow the parent to try.
		parentResult, _ := pm.parent.Authenticate(authentication)
		if parentResult != nil {
			result = parentResult
		}
	}

	if result != nil {
		if pm.eraseCredentialsAfterAuth {
			if credentialsContainer, ok := result.(CredentialsContainer); ok {
				credentialsContainer.EraseCredentials()
			}
		}
		if parentResult == nil {
			pm.eventPublisher.PublishAuthenticationSuccess(result)
		}
		return result, nil
	}

	if lastException == nil {
		lastException = NewAuthenticationExceptionWithoutCause("No AuthenticationProvider found")
	}

	if parentException == nil {
		pm.eventPublisher.PublishAuthenticationFailure(lastException, authentication)
	}
	return nil, lastException
}

func (pm *ProviderManager) copyDetails(source, dest Authentication) {
	if token, ok := dest.(*AbstractAuthenticationToken); ok && dest.GetDetails() == nil {
		token.SetDetails(source.GetDetails())
	}
}

// NullEventPublisher is an implementation of AuthenticationEventPublisher that does nothing.
type NullEventPublisher struct{}

func (n *NullEventPublisher) SetApplicationEventPublisher(publisher ApplicationEventPublisher) {
	//TODO implement me
	panic("implement me")
}

func (n *NullEventPublisher) SetAdditionalExceptionMappings(mappings map[reflect.Type]reflect.Type) {
	//TODO implement me
	panic("implement me")
}

func (n *NullEventPublisher) SetDefaultAuthenticationFailureEvent(eventClass reflect.Type) {
	//TODO implement me
	panic("implement me")
}

// PublishAuthenticationFailure does nothing when called.
func (n *NullEventPublisher) PublishAuthenticationFailure(exception *AuthenticationException, authentication Authentication) {
	// No operation
}

// PublishAuthenticationSuccess does nothing when called.
func (n *NullEventPublisher) PublishAuthenticationSuccess(authentication Authentication) {
	// No operation
}
