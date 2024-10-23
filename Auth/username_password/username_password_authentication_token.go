package username_password

type UsernamePasswordAuthenticationToken struct {
	username      string
	password      string
	authenticated bool
}

func NewUsernamePasswordAuthenticationToken(username string, password string) *UsernamePasswordAuthenticationToken {
	return &UsernamePasswordAuthenticationToken{
		username:      username,
		password:      password,
		authenticated: false,
	}
}

func (u *UsernamePasswordAuthenticationToken) GetCredentials() interface{} {
	return u.password
}

func (u *UsernamePasswordAuthenticationToken) GetDetails() interface{} {
	return nil
}

func (u *UsernamePasswordAuthenticationToken) GetPrincipal() interface{} {
	return u.username
}

func (u *UsernamePasswordAuthenticationToken) IsAuthenticated() bool {
	return u.authenticated
}

func (u *UsernamePasswordAuthenticationToken) SetAuthenticated(isAuthenticated bool) error {
	u.authenticated = isAuthenticated
	return nil
}
