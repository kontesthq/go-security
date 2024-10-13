package FromJava

import new2 "github.com/ayushs-2k4/go-security/Auth/new"

type AuthenticationProvider interface {
	Authenticate(authentication new2.Authentication) (new2.Authentication, *AuthenticationException)

	Supports(authType new2.Authentication) bool
}
