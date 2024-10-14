package PasswordEncoder

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava/PasswordEncoder/argon2"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava/PasswordEncoder/bcrypt"
	"github.com/ayushs-2k4/go-security/Auth/new/FromJava/PasswordEncoder/scrypt"
	"strings"
)

// DelegatingPasswordEncoder is a password encoder that delegates to another PasswordEncoder based on a prefixed identifier.
type DelegatingPasswordEncoder struct {
	idPrefix                         string
	idSuffix                         string
	IdForEncode                      string
	passwordEncoderForEncode         PasswordEncoder
	idToPasswordEncoder              map[string]PasswordEncoder
	defaultPasswordEncoderForMatches PasswordEncoder
}

func GetPasswordEncoders() map[string]PasswordEncoder {
	idToPasswordEncoder := map[string]PasswordEncoder{
		"bcrypt": bcrypt.NewBCryptPasswordEncoderWithStrength(10), // Implement BCryptPasswordEncoder
		"noop":   NewNoOpPasswordEncoder(),                        // Implement NoOpPasswordEncoder
		//"pbkdf2":             &Pbkdf2PasswordEncoder{},  // Implement Pbkdf2PasswordEncoder
		"scrypt": scrypt.NewSCryptPasswordEncoder(), // Implement SCryptPasswordEncoder
		//"sha256":             &StandardPasswordEncoder{}, // Implement StandardPasswordEncoder
		"argon2": argon2.NewArgon2PasswordEncoder(),
	}

	return idToPasswordEncoder
}

// NewDelegatingPasswordEncoder creates a new instance of DelegatingPasswordEncoder.
func NewDelegatingPasswordEncoder(idForEncode string, idToPasswordEncoder map[string]PasswordEncoder) (*DelegatingPasswordEncoder, error) {
	return NewDelegatingPasswordEncoderWithCustomPrefixSuffix(idForEncode, idToPasswordEncoder, "{", "}")
}

// NewDelegatingPasswordEncoderWithCustomPrefixSuffix creates a new instance with custom prefix and suffix.
func NewDelegatingPasswordEncoderWithCustomPrefixSuffix(idForEncode string, idToPasswordEncoder map[string]PasswordEncoder, idPrefix string, idSuffix string) (*DelegatingPasswordEncoder, error) {
	if idForEncode == "" {
		return nil, errors.New("IdForEncode cannot be empty")
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
		return nil, fmt.Errorf("IdForEncode %s is not found in idToPasswordEncoder", idForEncode)
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
		IdForEncode:                      idForEncode,
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
	finalEncodedPassword := fmt.Sprintf("%s%s%s%s", d.idPrefix, d.IdForEncode, d.idSuffix, encodedPassword)
	return finalEncodedPassword, nil // Return the final encoded string and nil for no error.
}

// Matches checks if the raw password matches the encoded password.
func (d *DelegatingPasswordEncoder) Matches(rawPassword string, prefixEncodedPassword string) (bool, error) {
	if rawPassword == "" && prefixEncodedPassword == "" {
		return true, nil
	}
	id := d.ExtractId(prefixEncodedPassword)
	delegate, ok := d.idToPasswordEncoder[id]
	if !ok {
		return d.defaultPasswordEncoderForMatches.Matches(rawPassword, prefixEncodedPassword)
	}
	encodedPassword := d.extractEncodedPassword(prefixEncodedPassword)
	return delegate.Matches(rawPassword, encodedPassword)
}

// ExtractId extracts the id from the prefix-encoded password.
func (d *DelegatingPasswordEncoder) ExtractId(prefixEncodedPassword string) string {
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
	id := d.ExtractId(prefixEncodedPassword)
	if id == "" {
		return prefixEncodedPassword
	}
	return prefixEncodedPassword[len(d.idPrefix)+len(id)+len(d.idSuffix):]
}

func (d *DelegatingPasswordEncoder) UpgradeEncoding(prefixEncodedPassword string) bool {
	id := d.ExtractId(prefixEncodedPassword)
	if !strings.EqualFold(d.IdForEncode, id) {
		return true
	} else {
		encodedPassword := d.extractEncodedPassword(prefixEncodedPassword)

		encoder, exists := d.idToPasswordEncoder[id]

		if exists {
			hasEncodingUpgraded, _ := encoder.UpgradeEncoding(encodedPassword)

			return hasEncodingUpgraded
		}
	}

	// If the encoder does not exist, return false
	return false
}
