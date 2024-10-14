package FromJava

type AuthenticationProvider interface {
	Authenticate(authentication Authentication) (Authentication, *AuthenticationException)

	Supports(authType Authentication) bool
}
