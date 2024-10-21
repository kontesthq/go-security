package ott

import (
	"github.com/google/uuid"
	"sync"
	"time"
)

type InMemoryOneTimeTokenService struct {
	oneTimeTokens map[string]DefaultOneTimeToken
	mutex         sync.Mutex
}

// NewInMemoryOneTimeTokenService creates a new instance of InMemoryOneTimeTokenService
func NewInMemoryOneTimeTokenService() *InMemoryOneTimeTokenService {
	return &InMemoryOneTimeTokenService{
		oneTimeTokens: make(map[string]DefaultOneTimeToken),
	}
}

func (s *InMemoryOneTimeTokenService) Generate(request GenerateOneTimeTokenRequest) OneTimeToken {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token := uuid.NewString()
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	ott := DefaultOneTimeToken{
		token:    token,
		username: request.Username,
		expireAt: expiresAt,
	}
	s.oneTimeTokens[token] = ott

	s.cleanExpiredTokensIfNeeded()
	return &ott
}

func (s *InMemoryOneTimeTokenService) Consume(authenticationToken OneTimeTokenAuthenticationToken) OneTimeToken {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Retrieve the token value from the authentication token
	tokenValue := authenticationToken.GetTokenValue()

	// Check if the token exists in the map
	ott, exists := s.oneTimeTokens[tokenValue]
	if exists && !s.isExpired(ott) {
		// Token is valid and not expired, so remove it from the map
		delete(s.oneTimeTokens, tokenValue)
		return &ott // Return a pointer to the token
	}
	return nil // Return nil if the token is invalid or expired
}

func (s *InMemoryOneTimeTokenService) cleanExpiredTokensIfNeeded() {
	if len(s.oneTimeTokens) >= 100 {
		for key, ott := range s.oneTimeTokens {
			if s.isExpired(ott) {
				delete(s.oneTimeTokens, key)
			}
		}
	}
}

func (s *InMemoryOneTimeTokenService) isExpired(ott DefaultOneTimeToken) bool {
	return time.Now().UTC().After(ott.GetExpiresAt())
}
