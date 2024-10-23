package Auth

type AuthenticationManager interface {
	Authenticate(authentication Authentication) (Authentication, error)
}
