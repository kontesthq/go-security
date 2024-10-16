package Auth

type UserDetails interface {
	GetUsername() string
	GetPassword() string
}
