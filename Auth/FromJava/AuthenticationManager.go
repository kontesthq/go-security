package FromJava

type AuthenticationManager interface {
	Authenticate(authentication Authentication) (Authentication, error)
}
