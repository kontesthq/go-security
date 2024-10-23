package security

import (
	"github.com/kontesthq/go-security/Auth"
)

type SecurityContext interface {
	GetAuthentication() Auth.Authentication

	SetAuthentication(auth Auth.Authentication) error
}
