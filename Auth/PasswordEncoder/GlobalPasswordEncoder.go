package PasswordEncoder

import (
	"sync"
)

type GlobalDelegatingPasswordEncoder struct {
	DelegatingPasswordEncoder *DelegatingPasswordEncoder
	once                      sync.Once
}

func (g *GlobalDelegatingPasswordEncoder) GetGlobalPasswordEncoder() *DelegatingPasswordEncoder {
	g.once.Do(
		func() {
			idForEncode := "argon2"
			encoders := GetPasswordEncoders()
			var err error
			g.DelegatingPasswordEncoder, err = NewDelegatingPasswordEncoder(idForEncode, encoders)
			if err != nil {
			}
		})

	return g.DelegatingPasswordEncoder
}
