package Store

import (
	"errors"
	"github.com/kontesthq/go-security/model"
)

// InMemoryUserStore is a simple in-memory implementation of UserStore.
type InMemoryUserStore struct {
	users         map[string]*model.User
	refreshTokens map[string]string // stores refresh tokens by email
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users:         make(map[string]*model.User),
		refreshTokens: make(map[string]string),
	}
}

func (store *InMemoryUserStore) FindUserByUsername(username string) (*model.User, error) {
	user, exists := store.users[username]
	if !exists {
		return nil, errors.New("user not found") // User not found
	}
	return user, nil
}

func (store *InMemoryUserStore) SaveRefreshToken(email, refreshToken string) error {
	if _, exists := store.users[email]; !exists {
		return errors.New("user not found")
	}
	store.refreshTokens[refreshToken] = email
	return nil
}

func (store *InMemoryUserStore) ValidateRefreshToken(refreshToken string) (string, error) {
	email, exists := store.refreshTokens[refreshToken]
	if !exists {
		return "", errors.New("invalid refresh token")
	}
	return email, nil
}

func (store *InMemoryUserStore) AddUser(username string, password string) {
	store.users[username] = &model.User{
		Username: username,
		Password: password,
	}
}

func (store *InMemoryUserStore) AddUsers(users map[string]string) {
	for username, password := range users {
		store.AddUser(username, password)
	}
}
