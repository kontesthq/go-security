package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"log"
	"math"
	"strconv"
	"strings"
)

const (
	DefaultCpuCost     = 65536
	DefaultMemoryCost  = 8
	DefaultParallelism = 1
	DefaultKeyLength   = 32
	DefaultSaltLength  = 16
)

type SCryptPasswordEncoder struct {
	cpuCost     int
	memoryCost  int
	parallelism int
	keyLength   int
	saltLength  int
	logger      *log.Logger
}

func NewSCryptPasswordEncoder() *SCryptPasswordEncoder {
	return &SCryptPasswordEncoder{
		cpuCost:     DefaultCpuCost,
		memoryCost:  DefaultMemoryCost,
		parallelism: DefaultParallelism,
		keyLength:   DefaultKeyLength,
		saltLength:  DefaultSaltLength,
		logger:      log.Default(),
	}
}

func NewSCryptPasswordEncoderWithValues(cpuCost, memoryCost, parallelization, keyLength, saltLength int) (*SCryptPasswordEncoder, error) {
	if cpuCost <= 1 {
		return nil, errors.New("Cpu cost parameter must be > 1.")
	}
	if memoryCost == 1 && cpuCost > 65536 {
		return nil, errors.New("Cpu cost parameter must be > 1 and < 65536.")
	}
	if memoryCost < 1 {
		return nil, errors.New("Memory cost must be >= 1.")
	}
	maxParallel := int(math.MaxInt32 / (128 * memoryCost * 8))
	if parallelization < 1 || parallelization > maxParallel {
		return nil, errors.New("Parallelization parameter must be >= 1 and <= " + string(maxParallel))
	}
	if keyLength < 1 || keyLength > math.MaxInt32 {
		return nil, errors.New("Key length must be >= 1 and <= " + string(math.MaxInt32))
	}
	if saltLength < 1 || saltLength > math.MaxInt32 {
		return nil, errors.New("Salt length must be >= 1 and <= " + string(math.MaxInt32))
	}

	return &SCryptPasswordEncoder{
		cpuCost:     cpuCost,
		memoryCost:  memoryCost,
		parallelism: parallelization,
		keyLength:   keyLength,
		saltLength:  saltLength,
		logger:      log.Default(),
	}, nil
}

func (encoder *SCryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	salt := generateRandomBytes(encoder.saltLength)
	derivedKey, err := scrypt.Key([]byte(rawPassword), salt, encoder.cpuCost, encoder.memoryCost, encoder.parallelism, encoder.keyLength)
	if err != nil {
		return "", err
	}

	// Encode parameters to a single hex string
	params := fmt.Sprintf("%x", (int(math.Log2(float64(encoder.cpuCost)))<<16)|(encoder.memoryCost<<8)|encoder.parallelism)
	encodedSalt := encodeBase64(salt)
	encodedDerived := encodeBase64(derivedKey)

	return fmt.Sprintf("$%s$%s$%s", params, encodedSalt, encodedDerived), nil
}

func (encoder *SCryptPasswordEncoder) Matches(rawPassword, encodedPassword string) (bool, error) {
	if len(encodedPassword) < encoder.keyLength {
		encoder.logger.Println("Empty encoded password")
		return false, errors.New("empty encoded password")
	}
	return encoder.decodeAndCheckMatches(rawPassword, encodedPassword), nil
}

// UpgradeEncoding checks if the encoding parameters are lower than the current parameters.
func (encoder *SCryptPasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	if encodedPassword == "" {
		return false, nil
	}

	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 4 {
		return false, errors.New("encoded password does not look like SCrypt")
	}

	params, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return false, err
	}

	cpuCost := int(math.Pow(2, float64(uint32(params)>>16&0xffff)))
	memoryCost := int(params >> 8 & 0xff)
	parallelization := int(params & 0xff)

	return cpuCost < encoder.cpuCost || memoryCost < encoder.memoryCost || parallelization < encoder.parallelism, nil
}

// decodeAndCheckMatches checks if the rawPassword matches the encodedPassword.
func (encoder *SCryptPasswordEncoder) decodeAndCheckMatches(rawPassword, encodedPassword string) bool {
	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 4 {
		return false
	}

	params, err := strconv.ParseUint(parts[1], 16, 64)
	salt, err := decodeBase64(parts[2])
	derived, err := decodeBase64(parts[3])

	cpuCost := int(math.Pow(2, float64(params>>16&0xffff)))
	memoryCost := int(params >> 8 & 0xff)
	parallelization := int(params & 0xff)

	// Generate the derived key using scrypt
	generated, err := scrypt.Key([]byte(rawPassword), salt, cpuCost, memoryCost, parallelization, encoder.keyLength)

	if err != nil {
		return false
	}

	// Compare the derived key with the generated key
	return subtle.ConstantTimeCompare(derived, generated) == 1
}

func generateRandomBytes(length int) []byte {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil
	}
	return salt
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
