package security

import (
	"github.com/ayushs-2k4/go-security/Auth"
)

type SecurityContext interface {
	GetAuthentication() Auth.Authentication

	SetAuthentication(auth Auth.Authentication) error
}
