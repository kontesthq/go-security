package security

import (
	"github.com/kontesthq/go-security/Auth"
)

type SecurityContextImpl struct {
	authentication Auth.Authentication
}

func (s *SecurityContextImpl) GetAuthentication() Auth.Authentication {
	return s.authentication
}

func (s *SecurityContextImpl) SetAuthentication(auth Auth.Authentication) error {
	s.authentication = auth

	return nil
}
