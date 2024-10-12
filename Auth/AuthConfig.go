package Auth

import "time"

type AuthConfig struct {
	JwtSecret   []byte
	TokenExpiry time.Duration
}
