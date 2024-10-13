package new

// GrantedAuthority represents a role or authority granted to a user.
type GrantedAuthority interface {
	GetAuthority() string
}

// SimpleGrantedAuthority is a simple implementation of GrantedAuthority.
type SimpleGrantedAuthority struct {
	Authority string
}

// GetAuthority returns the authority string.
func (s *SimpleGrantedAuthority) GetAuthority() string {
	return s.Authority
}
