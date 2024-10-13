package FromJava

import (
	"fmt"
	new2 "github.com/ayushs-2k4/go-security/Auth/new"
	"log"
	"reflect"
)

// AuthenticationEventPublisher defines an interface for publishing authentication events.
type AuthenticationEventPublisher interface {
	PublishAuthenticationSuccess(authentication new2.Authentication)
	PublishAuthenticationFailure(exception *AuthenticationException, authentication new2.Authentication)
	SetApplicationEventPublisher(publisher ApplicationEventPublisher)
	SetAdditionalExceptionMappings(mappings map[reflect.Type]reflect.Type)
	SetDefaultAuthenticationFailureEvent(eventClass reflect.Type)
}

// DefaultAuthenticationEventPublisher is the default implementation of AuthenticationEventPublisher.
type DefaultAuthenticationEventPublisher struct {
	logger                                       *log.Logger
	applicationEventPublisher                    ApplicationEventPublisher
	exceptionMappings                            map[reflect.Type]reflect.Type
	defaultAuthenticationFailureEventConstructor reflect.Type
}

// NewDefaultAuthenticationEventPublisher creates a new instance of DefaultAuthenticationEventPublisher.
func NewDefaultAuthenticationEventPublisher(publisher ApplicationEventPublisher) *DefaultAuthenticationEventPublisher {
	d := &DefaultAuthenticationEventPublisher{
		logger:                    log.Default(),
		applicationEventPublisher: publisher,
		exceptionMappings:         make(map[reflect.Type]reflect.Type),
	}

	// Add default mappings
	d.addMapping(reflect.TypeOf(BadCredentialsException{}), reflect.TypeOf(AuthenticationFailureBadCredentialsEvent{}))
	d.addMapping(reflect.TypeOf(UsernameNotFoundException{}), reflect.TypeOf(AuthenticationFailureBadCredentialsEvent{}))
	d.addMapping(reflect.TypeOf(AccountExpiredException{}), reflect.TypeOf(AuthenticationFailureExpiredEvent{}))
	d.addMapping(reflect.TypeOf(ProviderNotFoundException{}), reflect.TypeOf(AuthenticationFailureProviderNotFoundEvent{}))
	d.addMapping(reflect.TypeOf(DisabledException{}), reflect.TypeOf(AuthenticationFailureDisabledEvent{}))
	d.addMapping(reflect.TypeOf(LockedException{}), reflect.TypeOf(AuthenticationFailureLockedEvent{}))
	d.addMapping(reflect.TypeOf(AuthenticationServiceException{}), reflect.TypeOf(AuthenticationFailureServiceExceptionEvent{}))
	d.addMapping(reflect.TypeOf(CredentialsExpiredException{}), reflect.TypeOf(AuthenticationFailureCredentialsExpiredEvent{}))
	d.addMapping(reflect.TypeOf(ProxyUntrustedException{}), reflect.TypeOf(AuthenticationFailureProxyUntrustedEvent{}))
	d.addMapping(reflect.TypeOf(InvalidBearerTokenException{}), reflect.TypeOf(AuthenticationFailureBadCredentialsEvent{}))

	return d
}

// PublishAuthenticationSuccess publishes a successful authentication event.
func (d *DefaultAuthenticationEventPublisher) PublishAuthenticationSuccess(authentication new2.Authentication) {
	if d.applicationEventPublisher != nil {
		event := &AuthenticationSuccessEvent{Authentication: authentication}
		d.applicationEventPublisher.PublishEvent(event)
	}
}

// PublishAuthenticationFailure publishes a failed authentication event.
func (d *DefaultAuthenticationEventPublisher) PublishAuthenticationFailure(exception AuthenticationException, authentication new2.Authentication) {
	constructor := d.getEventConstructor(exception)
	var event AbstractAuthenticationEvent

	if constructor != nil {
		event = reflect.New(constructor).Interface().(AbstractAuthenticationEvent)
		event.Authentication = authentication
		event.Exception = exception
		if d.applicationEventPublisher != nil {
			d.applicationEventPublisher.PublishEvent(event)
		}
	} else {
		d.logger.Println("No event was found for the exception", reflect.TypeOf(exception).Name())
	}
}

func (d *DefaultAuthenticationEventPublisher) getEventConstructor(exception AuthenticationException) reflect.Type {
	eventConstructor, exists := d.exceptionMappings[reflect.TypeOf(exception)]
	if exists {
		return eventConstructor
	}
	return d.defaultAuthenticationFailureEventConstructor
}

// SetApplicationEventPublisher sets the application event publisher.
func (d *DefaultAuthenticationEventPublisher) SetApplicationEventPublisher(publisher ApplicationEventPublisher) {
	d.applicationEventPublisher = publisher
}

// SetAdditionalExceptionMappings sets additional exception-to-event mappings.
func (d *DefaultAuthenticationEventPublisher) SetAdditionalExceptionMappings(mappings map[reflect.Type]reflect.Type) {
	if len(mappings) == 0 {
		return
	}
	for exceptionClass, eventClass := range mappings {
		d.addMapping(exceptionClass, eventClass)
	}
}

// SetDefaultAuthenticationFailureEvent sets the default authentication failure event.
func (d *DefaultAuthenticationEventPublisher) SetDefaultAuthenticationFailureEvent(eventClass reflect.Type) {
	if eventClass == nil {
		panic("defaultAuthenticationFailureEventClass must not be nil")
	}
	d.defaultAuthenticationFailureEventConstructor = eventClass
}

// addMapping adds a mapping from an exception class to an event class.
func (d *DefaultAuthenticationEventPublisher) addMapping(exceptionClass reflect.Type, eventClass reflect.Type) {
	if eventClass.NumIn() != 2 {
		panic(fmt.Sprintf("Authentication event class %s has no suitable constructor", eventClass.Name()))
	}
	d.exceptionMappings[exceptionClass] = eventClass
}

// Other necessary types and interfaces would need to be defined below
type ApplicationEventPublisher interface {
	PublishEvent(event interface{})
}

//type Authentication struct{}

type AbstractAuthenticationEvent struct {
	Authentication new2.Authentication
	Exception      AuthenticationException
}

type AuthenticationSuccessEvent struct {
	Authentication new2.Authentication
}

type BadCredentialsException struct{}
type UsernameNotFoundException struct{}
type AccountExpiredException struct{}
type ProviderNotFoundException struct{}
type DisabledException struct{}
type LockedException struct{}
type AuthenticationServiceException struct{}
type CredentialsExpiredException struct{}
type ProxyUntrustedException struct{}
type InvalidBearerTokenException struct{}
type AuthenticationFailureBadCredentialsEvent struct{}
type AuthenticationFailureExpiredEvent struct{}
type AuthenticationFailureProviderNotFoundEvent struct{}
type AuthenticationFailureDisabledEvent struct{}
type AuthenticationFailureLockedEvent struct{}
type AuthenticationFailureServiceExceptionEvent struct{}
type AuthenticationFailureCredentialsExpiredEvent struct{}
type AuthenticationFailureProxyUntrustedEvent struct{}
