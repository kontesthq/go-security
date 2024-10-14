package argon2

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"log"
	"strings"
)

// Argon2PasswordEncoder implements a password encoder using Argon2.
type Argon2PasswordEncoder struct {
	hashLength  uint32
	parallelism uint8
	memory      uint32
	iterations  uint32
	saltLength  int
}

const (
	DefaultSaltLength  = 16
	DefaultHashLength  = 32
	DefaultParallelism = 1
	DefaultMemory      = 1 << 14
	DefaultIterations  = 2
)

// NewArgon2PasswordEncoder constructs an Argon2PasswordEncoder with the provided parameters.
func NewArgon2PasswordEncoder() *Argon2PasswordEncoder {
	return &Argon2PasswordEncoder{
		saltLength:  DefaultSaltLength,
		hashLength:  DefaultHashLength,
		parallelism: DefaultParallelism,
		memory:      DefaultMemory,
		iterations:  DefaultIterations,
	}
}

// NewArgon2PasswordEncoderWithValues constructs an Argon2PasswordEncoder with the provided parameters.
func NewArgon2PasswordEncoderWithValues(saltLength int, hashLength uint32, parallelism uint8, memory uint32, iterations uint32) *Argon2PasswordEncoder {
	return &Argon2PasswordEncoder{
		saltLength:  saltLength,
		hashLength:  hashLength,
		parallelism: parallelism,
		memory:      memory,
		iterations:  iterations,
	}
}

// Encode hashes the raw password with Argon2 and returns the encoded string.
func (encoder *Argon2PasswordEncoder) Encode(rawPassword string) (string, error) {
	salt := make([]byte, encoder.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(rawPassword), salt, encoder.iterations, encoder.memory, encoder.parallelism, encoder.hashLength)

	// Encode salt and hash to a single string
	encoded := fmt.Sprintf("%s$%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash))
	return encoded, nil
}

// Matches compares the raw password with the encoded password.
func (encoder *Argon2PasswordEncoder) Matches(rawPassword, encodedPassword string) (bool, error) {
	if encodedPassword == "" {
		log.Println("password hash is null")
		return false, errors.New("password hash is null")
	}

	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 2 {
		log.Println("Malformed password hash")
		return false, errors.New("malformed password hash")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		log.Println("Failed to decode salt:", err)
		return false, errors.New(fmt.Sprintf("failed to decode salt: %f", err))
	}

	// Decode hash
	hash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		log.Println("Failed to decode hash:", err)
		return false, errors.New(fmt.Sprintf("failed to decode hash: %f", err))
	}

	// Generate hash from raw password using the same salt
	generatedHash := argon2.IDKey([]byte(rawPassword), salt, encoder.iterations, encoder.memory, encoder.parallelism, encoder.hashLength)
	return constantTimeArrayEquals(hash, generatedHash), nil
}

// UpgradeEncoding checks if the encoding parameters need to be upgraded.
func (encoder *Argon2PasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	if encodedPassword == "" {
		log.Println("password hash is null")
		return false, errors.New("password hash is null")
	}

	argon2Hash, err := Decode(encodedPassword)
	if err != nil {
		//encoder.Logger.Println("error decoding password hash:", err)
		return false, err
	}

	parameters := argon2Hash.Parameters
	return uint32(parameters.Memory) < encoder.memory || uint32(parameters.Iterations) < encoder.iterations, nil
}

// constantTimeArrayEquals compares two byte slices in constant time.
func constantTimeArrayEquals(expected, actual []byte) bool {
	if len(expected) != len(actual) {
		return false
	}
	result := 0
	for i := range expected {
		result |= int(expected[i] ^ actual[i])
	}
	return result == 0
}
