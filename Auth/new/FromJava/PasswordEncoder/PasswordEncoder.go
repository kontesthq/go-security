package PasswordEncoder

// Service interface for encoding passwords.
// The preferred implementation is {@code BCryptPasswordEncoder}.

type PasswordEncoder interface {
	Encode(rawPassword string) (string, error)

	Matches(rawPassword, encodedPassword string) bool

	UpgradeEncoding(encodedPassword string) (bool, error)
}
