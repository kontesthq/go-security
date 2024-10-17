package Auth

import (
	"github.com/ayushs-2k4/go-security/Auth/PasswordEncoder"
	"sync"
)

type GlobalDelegatingPasswordEncoder struct {
	DelegatingPasswordEncoder *PasswordEncoder.DelegatingPasswordEncoder
	once                      sync.Once
}

func (g *GlobalDelegatingPasswordEncoder) GetGlobalPasswordEncoder() *PasswordEncoder.DelegatingPasswordEncoder {
	g.once.Do(
		func() {
			idForEncode := "argon2"
			encoders := PasswordEncoder.GetPasswordEncoders()
			var err error
			g.DelegatingPasswordEncoder, err = PasswordEncoder.NewDelegatingPasswordEncoder(idForEncode, encoders)
			if err != nil {
			}
		})

	return g.DelegatingPasswordEncoder
}
