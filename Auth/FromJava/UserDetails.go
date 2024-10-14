package FromJava

// UserDetails represents user information for authentication
type UserDetails interface {
	GetAuthorities() []GrantedAuthority
	GetPassword() string
	GetUsername() string
	IsAccountNonExpired() bool
	IsAccountNonLocked() bool
	IsCredentialsNonExpired() bool
	IsEnabled() bool
}
