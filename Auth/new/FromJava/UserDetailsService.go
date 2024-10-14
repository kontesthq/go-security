package FromJava

// UserDetailsService handles user details.
type UserDetailsService interface {
	LoadUserByUsername(username string) (UserDetails, error)
}
