package auth

import "time"

type AuthConfig struct {
	JwtSecret   []byte
	TokenExpiry time.Duration
}
