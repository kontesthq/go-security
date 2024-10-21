package ott

import (
	"errors"
	"time"
)

// DefaultOneTimeToken struct implements the OneTimeToken interface
type DefaultOneTimeToken struct {
	token    string
	username string
	expireAt time.Time
}

// NewDefaultOneTimeToken creates a new DefaultOneTimeToken
func NewDefaultOneTimeToken(token, username string, expireAt time.Time) (*DefaultOneTimeToken, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if expireAt.IsZero() {
		return nil, errors.New("expireAt cannot be zero")
	}
	return &DefaultOneTimeToken{
		token:    token,
		username: username,
		expireAt: expireAt,
	}, nil
}

// GetTokenValue returns the token value
func (t *DefaultOneTimeToken) GetTokenValue() string {
	return t.token
}

// GetUsername returns the username
func (t *DefaultOneTimeToken) GetUsername() string {
	return t.username
}

// GetExpiresAt returns the expiration time
func (t *DefaultOneTimeToken) GetExpiresAt() time.Time {
	return t.expireAt
}
