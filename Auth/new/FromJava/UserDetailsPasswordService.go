package FromJava

import new2 "github.com/ayushs-2k4/go-security/Auth/new"

type UserDetailsPasswordService interface {
	UpdatePassword(user new2.UserDetails, newPassword string) new2.UserDetails
}
