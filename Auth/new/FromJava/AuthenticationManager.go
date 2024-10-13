package FromJava

import new2 "github.com/ayushs-2k4/go-security/Auth/new"

type AuthenticationManager interface {
	Authenticate(authentication new2.Authentication) new2.Authentication
}
