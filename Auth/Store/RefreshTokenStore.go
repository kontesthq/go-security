package Store

import "errors"

type RefreshTokenStore interface {
	Save(refreshToken, subject string) error
	FindSubject(refreshToken string) (string, error)
	Delete(refreshToken string) error
}

// InMemoryRefreshTokenStore is a simple in-memory implementation of RefreshTokenStore.
type InMemoryRefreshTokenStore struct {
	tokens map[string]string
}

// NewInMemoryRefreshTokenStore creates a New instance of InMemoryRefreshTokenStore.
func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{
		tokens: make(map[string]string),
	}
}

// Save saves a refresh token and associated username.
func (store *InMemoryRefreshTokenStore) Save(refreshToken, username string) error {
	store.tokens[refreshToken] = username
	return nil
}

// FindSubject retrieves the username associated with a refresh token.
func (store *InMemoryRefreshTokenStore) FindSubject(refreshToken string) (string, error) {
	username, ok := store.tokens[refreshToken]
	if !ok {
		return "", errors.New("refresh token not found")
	}
	return username, nil
}

// Delete removes a refresh token from storage.
func (store *InMemoryRefreshTokenStore) Delete(refreshToken string) error {
	delete(store.tokens, refreshToken)
	return nil
}
