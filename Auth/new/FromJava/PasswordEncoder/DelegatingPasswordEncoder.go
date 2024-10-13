package PasswordEncoder

import (
	"errors"
	"fmt"
	"strings"
)

// DelegatingPasswordEncoder is a password encoder that delegates to another PasswordEncoder based on a prefixed identifier.
type DelegatingPasswordEncoder struct {
	idPrefix                         string
	idSuffix                         string
	idForEncode                      string
	passwordEncoderForEncode         PasswordEncoder
	idToPasswordEncoder              map[string]PasswordEncoder
	defaultPasswordEncoderForMatches PasswordEncoder
}

// NewDelegatingPasswordEncoder creates a new instance of DelegatingPasswordEncoder.
func NewDelegatingPasswordEncoder(idForEncode string, idToPasswordEncoder map[string]PasswordEncoder) (*DelegatingPasswordEncoder, error) {
	return NewDelegatingPasswordEncoderWithCustomPrefixSuffix(idForEncode, idToPasswordEncoder, "{", "}")
}

// NewDelegatingPasswordEncoderWithCustomPrefixSuffix creates a new instance with custom prefix and suffix.
func NewDelegatingPasswordEncoderWithCustomPrefixSuffix(idForEncode string, idToPasswordEncoder map[string]PasswordEncoder, idPrefix string, idSuffix string) (*DelegatingPasswordEncoder, error) {
	if idForEncode == "" {
		return nil, errors.New("idForEncode cannot be empty")
	}
	if idPrefix == "" {
		return nil, errors.New("prefix cannot be empty")
	}
	if idSuffix == "" {
		return nil, errors.New("suffix cannot be empty")
	}
	if strings.Contains(idPrefix, idSuffix) {
		return nil, fmt.Errorf("idPrefix %s cannot contain idSuffix %s", idPrefix, idSuffix)
	}
	if _, ok := idToPasswordEncoder[idForEncode]; !ok {
		return nil, fmt.Errorf("idForEncode %s is not found in idToPasswordEncoder", idForEncode)
	}

	for id := range idToPasswordEncoder {
		if id != "" {
			if strings.Contains(id, idPrefix) {
				return nil, fmt.Errorf("id %s cannot contain %s", id, idPrefix)
			}
			if strings.Contains(id, idSuffix) {
				return nil, fmt.Errorf("id %s cannot contain %s", id, idSuffix)
			}
		}
	}

	return &DelegatingPasswordEncoder{
		idPrefix:                         idPrefix,
		idSuffix:                         idSuffix,
		idForEncode:                      idForEncode,
		passwordEncoderForEncode:         idToPasswordEncoder[idForEncode],
		idToPasswordEncoder:              idToPasswordEncoder,
		defaultPasswordEncoderForMatches: &UnmappedIdPasswordEncoder{},
	}, nil
}

// SetDefaultPasswordEncoderForMatches sets the encoder to delegate to if the id is not mapped.
func (d *DelegatingPasswordEncoder) SetDefaultPasswordEncoderForMatches(encoder PasswordEncoder) error {
	if encoder == nil {
		return errors.New("defaultPasswordEncoderForMatches cannot be nil")
	}
	d.defaultPasswordEncoderForMatches = encoder
	return nil
}

// Encode encodes the raw password using the configured PasswordEncoder.
func (d *DelegatingPasswordEncoder) Encode(rawPassword string) (string, error) {
	// Encode the password using the configured encoder.
	encodedPassword, err := d.passwordEncoderForEncode.Encode(rawPassword)
	if err != nil {
		return "", err // Return an empty string and the error if encoding fails.
	}

	// Construct the final encoded string with prefixes and suffixes.
	finalEncodedPassword := fmt.Sprintf("%s%s%s%s", d.idPrefix, d.idForEncode, d.idSuffix, encodedPassword)
	return finalEncodedPassword, nil // Return the final encoded string and nil for no error.
}

// Matches checks if the raw password matches the encoded password.
func (d *DelegatingPasswordEncoder) Matches(rawPassword string, prefixEncodedPassword string) (bool, error) {
	if rawPassword == "" && prefixEncodedPassword == "" {
		return true, nil
	}
	id := d.extractId(prefixEncodedPassword)
	delegate, ok := d.idToPasswordEncoder[id]
	if !ok {
		return d.defaultPasswordEncoderForMatches.Matches(rawPassword, prefixEncodedPassword)
	}
	encodedPassword := d.extractEncodedPassword(prefixEncodedPassword)
	return delegate.Matches(rawPassword, encodedPassword)
}

// extractId extracts the id from the prefix-encoded password.
func (d *DelegatingPasswordEncoder) extractId(prefixEncodedPassword string) string {
	if prefixEncodedPassword == "" {
		return ""
	}
	start := strings.Index(prefixEncodedPassword, d.idPrefix)
	if start != 0 {
		return ""
	}
	end := strings.Index(prefixEncodedPassword, d.idSuffix)
	if end < 0 {
		return ""
	}
	return prefixEncodedPassword[start+len(d.idPrefix) : end]
}

// extractEncodedPassword extracts the encoded password from the prefix-encoded password.
func (d *DelegatingPasswordEncoder) extractEncodedPassword(prefixEncodedPassword string) string {
	id := d.extractId(prefixEncodedPassword)
	if id == "" {
		return prefixEncodedPassword
	}
	return prefixEncodedPassword[len(d.idPrefix)+len(id)+len(d.idSuffix):]
}

// UnmappedIdPasswordEncoder is a default encoder for unmapped ids.
type UnmappedIdPasswordEncoder struct{}

// Encode does nothing and returns the raw password.
func (u *UnmappedIdPasswordEncoder) Encode(rawPassword string) (string, error) {
	return rawPassword, nil
}

// Matches always returns false for unmapped ids.
func (u *UnmappedIdPasswordEncoder) Matches(rawPassword string, encodedPassword string) (bool, error) {
	// For unmapped IDs, we do not check the password; we return false.
	return false, nil
}

func (u *UnmappedIdPasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	return false, nil
}

// Example usage (implementations of PasswordEncoder needed for real usage).
func main() {
	// Example usage
	idForEncode := "bcrypt"
	idToPasswordEncoder := map[string]PasswordEncoder{
		idForEncode: &BCryptPasswordEncoder{}, // Implement BCryptPasswordEncoder
		"noop":      &NoOpPasswordEncoder{},   // Implement NoOpPasswordEncoder
		//"pbkdf2":             &Pbkdf2PasswordEncoder{},  // Implement Pbkdf2PasswordEncoder
		"scrypt": &SCryptPasswordEncoder{}, // Implement SCryptPasswordEncoder
		//"sha256":             &StandardPasswordEncoder{}, // Implement StandardPasswordEncoder
	}

	encoder, err := NewDelegatingPasswordEncoder(idForEncode, idToPasswordEncoder)
	if err != nil {
		fmt.Println("Error creating DelegatingPasswordEncoder:", err)
		return
	}

	rawPassword := "password"
	encoded, err := encoder.Encode(rawPassword)
	fmt.Println("Encoded password:", encoded)

	match, err := encoder.Matches(rawPassword, encoded)
	fmt.Println("Password matches:", match)
}
