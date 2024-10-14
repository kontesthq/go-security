package PasswordEncoder

import (
	"github.com/ayushs-2k4/go-security/Auth/FromJava/PasswordEncoder/bcrypt"
	"github.com/ayushs-2k4/go-security/Auth/FromJava/PasswordEncoder/scrypt"
)

type PasswordEncoderFactories struct {
}

// CreateDelegatingPasswordEncoder creates a DelegatingPasswordEncoder with default mappings.
// Additional mappings may be added and the encoding will be updated to conform with best practices.
// The current mappings are:
// - bcrypt: BCryptPasswordEncoder
// - noop: NoOpPasswordEncoder
// - scrypt: SCryptPasswordEncoder
func (p *PasswordEncoderFactories) CreateDelegatingPasswordEncoder() (*DelegatingPasswordEncoder, error) {
	encodingId := "bcrypt"
	encoders := map[string]PasswordEncoder{
		encodingId: new(bcrypt.BCryptPasswordEncoder),
		"noop":     new(NoOpPasswordEncoder),
		"scrypt":   new(scrypt.SCryptPasswordEncoder),
		// Add other encoders as needed.
	}

	return NewDelegatingPasswordEncoder(encodingId, encoders)
}
