package PasswordEncoder

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/rand/v2"
	"regexp"
	"strconv"
)

// BCryptVersion represents the supported versions of bcrypt.
type BCryptVersion struct {
	version string
}

// Supported bcrypt versions.
var (
	BCryptVersion2A = BCryptVersion{version: "$2a"}
	BCryptVersion2B = BCryptVersion{version: "$2b"}
	BCryptVersion2Y = BCryptVersion{version: "$2y"}
)

// BCryptPasswordEncoder is an implementation of PasswordEncoder that uses bcrypt for hashing passwords.
type BCryptPasswordEncoder struct {
	BCRYPT_PATTERN *regexp.Regexp // Regex pattern for matching BCrypt format
	logger         *log.Logger    // Logger for logging warnings or errors
	strength       int            // Strength of the BCrypt encoder (cost factor)
	version        BCryptVersion  // Version of bcrypt to use
	random         *rand.Rand     // Secure random instance to use
}

// NewBCryptPasswordEncoder creates a new instance of BCryptPasswordEncoder with the specified strength.
func NewBCryptPasswordEncoder() *BCryptPasswordEncoder {
	return NewBCryptPasswordEncoderWithStrength(-1)
}

// NewBCryptPasswordEncoderWithStrength creates a new instance of BCryptPasswordEncoder with specified strength.
func NewBCryptPasswordEncoderWithStrength(strength int) *BCryptPasswordEncoder {
	return NewBCryptPasswordEncoderWithVersionAndStrength(BCryptVersion2A, strength, nil)
}

// NewBCryptPasswordEncoderWithVersion creates a new instance of BCryptPasswordEncoder with specified version.
func NewBCryptPasswordEncoderWithVersion(version BCryptVersion) *BCryptPasswordEncoder {
	return NewBCryptPasswordEncoderWithVersionAndStrength(version, -1, nil)
}

// NewBCryptPasswordEncoderWithVersionAndRandom creates a new instance with the specified version and a secure random instance.
func NewBCryptPasswordEncoderWithVersionAndRandom(version BCryptVersion, random *rand.Rand) *BCryptPasswordEncoder {
	return NewBCryptPasswordEncoderWithVersionAndStrength(version, -1, random)
}

// NewBCryptPasswordEncoderWithStrengthAndRandom creates a new instance with the specified strength and a secure random instance.
func NewBCryptPasswordEncoderWithStrengthAndRandom(strength int, random *rand.Rand) *BCryptPasswordEncoder {
	return NewBCryptPasswordEncoderWithVersionAndStrength(BCryptVersion2A, strength, random)
}

// NewBCryptPasswordEncoderWithVersionAndStrength creates a new instance with the specified version and strength.
func NewBCryptPasswordEncoderWithVersionAndStrength(version BCryptVersion, strength int, random *rand.Rand) *BCryptPasswordEncoder {
	if strength != -1 && (strength < 4 || strength > 31) {
		panic(errors.New("Bad strength: must be between 4 and 31"))
	}
	if strength == -1 {
		strength = 10 // Default strength
	}
	// Compile the regex pattern for matching BCrypt format.
	pattern := regexp.MustCompile(`\A\$2(a|y|b)?\$(\d\d)\$[./0-9A-Za-z]{53}`)
	return &BCryptPasswordEncoder{
		BCRYPT_PATTERN: pattern,
		logger:         log.Default(),
		strength:       strength,
		version:        version,
		random:         random,
	}
}

// Encode hashes the provided raw password using BCrypt and returns the hashed password.
func (b *BCryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	if rawPassword == "" {
		return "", errors.New("rawPassword cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), b.strength)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

// Matches checks if the provided raw password matches the stored hashed password.
func (b *BCryptPasswordEncoder) Matches(rawPassword, encodedPassword string) (bool, error) {
	if rawPassword == "" {
		panic(errors.New("rawPassword cannot be empty"))
	}
	if encodedPassword == "" {
		b.logger.Println("Empty encoded password")
		return false, errors.New("empty encoded password")
	}
	if !b.BCRYPT_PATTERN.MatchString(encodedPassword) {
		b.logger.Println("Encoded password does not look like BCrypt")
		return false, errors.New("encoded password does not look like BCrypt")
	}
	return bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(rawPassword)) == nil, nil
}

// UpgradeEncoding checks if the provided encoded password needs to be rehashed.
func (b *BCryptPasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	if encodedPassword == "" {
		b.logger.Println("Empty encoded password")
		return false, errors.New("empty encoded password")
	}
	matches := b.BCRYPT_PATTERN.FindStringSubmatch(encodedPassword)
	if matches == nil {
		panic(errors.New("Encoded password does not look like BCrypt"))
	}
	strength, err := strconv.Atoi(matches[2])
	if err != nil {
		b.logger.Println("Error parsing strength:", err)
		return false, err
	}
	return strength < b.strength, nil // Return true if the current strength is less than the configured strength
}
