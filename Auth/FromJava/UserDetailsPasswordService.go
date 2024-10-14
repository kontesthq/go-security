package FromJava

type UserDetailsPasswordService interface {
	UpdatePassword(user UserDetails, newPassword string) UserDetails
}
