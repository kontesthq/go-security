package FromJava

import new2 "github.com/ayushs-2k4/go-security/Auth/new"

type UserDetailsChecker interface {
	Check(toCheck new2.UserDetails) error
}
