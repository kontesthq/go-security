package PasswordEncoder

// NoOpPasswordEncoder is a PasswordEncoder that performs no encoding.
type NoOpPasswordEncoder struct{}

// NewNoOpPasswordEncoder creates a New instance of NoOpPasswordEncoder.
func NewNoOpPasswordEncoder() *NoOpPasswordEncoder {
	return &NoOpPasswordEncoder{}
}

// Encode returns the raw password as-is.
func (n *NoOpPasswordEncoder) Encode(rawPassword string) (string, error) {
	return rawPassword, nil
}

// Matches checks if the raw password matches the encoded password.
func (n *NoOpPasswordEncoder) Matches(rawPassword, encodedPassword string) (bool, error) {
	return rawPassword == encodedPassword, nil
}

func (n *NoOpPasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	return false, nil
}

// GetInstance returns a singleton instance of NoOpPasswordEncoder.
func GetInstance() PasswordEncoder {
	return NewNoOpPasswordEncoder()
}
