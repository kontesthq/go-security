package ott

import "time"

type OneTimeToken interface {
	GetTokenValue() string

	GetUsername() string

	GetExpiresAt() time.Time
}
