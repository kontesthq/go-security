package PasswordEncoder

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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

func NewSCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength int) (*SCryptPasswordEncoder, error) {
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

func (s *SCryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	salt := generateRandomBytes(s.saltLength)
	derivedKey, err := scrypt.Key([]byte(rawPassword), salt, s.cpuCost, s.memoryCost, s.parallelism, s.keyLength)
	if err != nil {
		return "", err
	}

	params := fmt.Sprintf("%x", ((int(math.Log2(float64(s.cpuCost))) << 16) | (s.memoryCost << 8) | s.parallelism))
	encodedSalt := encodeBase64(salt)
	encodedDerived := encodeBase64(derivedKey)

	return fmt.Sprintf("$%s$%s$%s", params, encodedSalt, encodedDerived), nil
}

func (s *SCryptPasswordEncoder) Matches(rawPassword, encodedPassword string) bool {
	if len(encodedPassword) < s.keyLength {
		s.logger.Println("Empty encoded password")
		return false
	}
	return s.decodeAndCheckMatches(rawPassword, encodedPassword)
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

func (s *SCryptPasswordEncoder) decodeAndCheckMatches(rawPassword, encodedPassword string) bool {
	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 4 {
		return false
	}

	params, _ := hex.DecodeString(parts[1])
	salt, _ := decodeBase64(parts[2])
	derived, _ := decodeBase64(parts[3])

	cpuCost := int(math.Pow(2, float64(uint32(params[0])>>16&0xffff)))
	memoryCost := int(params[0] >> 8 & 0xff)
	parallelization := int(params[0] & 0xff)

	generated, err := scrypt.Key([]byte(rawPassword), salt, cpuCost, memoryCost, parallelization, s.keyLength)
	if err != nil {
		return false
	}
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
