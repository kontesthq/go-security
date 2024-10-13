package new

import (
	"golang.org/x/crypto/bcrypt"
)

// PasswordEncoder encodes and checks passwords.
type PasswordEncoder interface {
	Encode(rawPassword string) (string, error)
	Matches(rawPassword, encodedPassword string) bool
	UpgradeEncoding(encodedPassword string) bool
}

// BCryptPasswordEncoder is an implementation of PasswordEncoder using BCrypt.
type BCryptPasswordEncoder struct{}

// Encode encodes the password using BCrypt.
func (b *BCryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Matches checks if the raw password matches the encoded password.
func (b *BCryptPasswordEncoder) Matches(rawPassword, encodedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(rawPassword))
	return err == nil
}
