package argon2

import (
	"crypto/rand"
	"errors"
	error3 "github.com/ayushs-2k4/go-security/Auth/PasswordEncoder/error"
	error2 "github.com/ayushs-2k4/go-security/Auth/error"
	"golang.org/x/crypto/argon2"
	"log"
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

	argon2Parameters, err := NewArgon2Parameters(Argon2id, int(encoder.memory), int(encoder.iterations), int(encoder.parallelism), salt)

	if err != nil {
		return "", err
	}

	encoded, err := Encode(hash, argon2Parameters)
	if err != nil {
		return "", err
	}

	// Encode salt and hash to a single string
	return encoded, nil
}

// Matches compares the raw password with the encoded password.
func (encoder *Argon2PasswordEncoder) Matches(rawPassword, encodedPassword string) (bool, error) {
	if encodedPassword == "" {
		return false, &error3.PasswordHashNullError{}
	}

	decoded, err := Decode(encodedPassword)

	if err != nil {
		return false, err
	}

	hashBytes := decoded.Hash
	parameters := decoded.Parameters

	// Validate the extracted parameters
	if len(hashBytes) == 0 || parameters.Salt == nil {
		log.Println("Decoded password hash or salt is empty")
		return false, errors.New("decoded password hash or salt is empty")
	}

	// Generate a hash from the raw password using the extracted parameters
	generatedHash := argon2.IDKey([]byte(rawPassword), parameters.Salt, uint32(parameters.Iterations), uint32(parameters.Memory), uint8(parameters.Lanes), uint32(len(hashBytes)))

	// Perform a constant-time comparison of the two hashes for security
	if constantTimeArrayEquals(hashBytes, generatedHash) {
		return true, nil
	}

	log.Println("Password hashes do not match")
	return false, &error2.PasswordHashNotMatchError{}
}

// UpgradeEncoding checks if the encoding parameters need to be upgraded.
func (encoder *Argon2PasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	if encodedPassword == "" {
		return false, &error3.PasswordHashNullError{}
	}

	argon2Hash, err := Decode(encodedPassword)
	if err != nil {
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
