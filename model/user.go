package model

type User struct {
	ID       string
	Username string
	Password string
}

// UserStore defines methods for user storage.
type UserStore interface {
	// FindUserByUsername retrieves a user by their email.
	FindUserByUsername(username string) (*User, error)

	// SaveRefreshToken stores the refresh token for a user.
	SaveRefreshToken(username, refreshToken string) error

	// ValidateRefreshToken checks if the refresh token is valid.
	ValidateRefreshToken(refreshToken string) (string, error) // returns email if valid
}
