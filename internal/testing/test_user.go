package testing

type TestUser struct {
	Username string
	Password string
	Leetcode string
}

type TestUserPrincipal struct {
	User TestUser
}

func (u TestUserPrincipal) GetUsername() string {
	return u.User.Username
}

func (u TestUserPrincipal) GetPassword() string {
	return u.User.Password
}
