package argon2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Argon2Parameters holds the parameters for Argon2 hashing.
type Argon2Parameters struct {
	Type       int
	Version    int
	Memory     int
	Iterations int
	Lanes      int
	Salt       []byte
}

// NewArgon2Parameters creates a new Argon2Parameters instance with provided values.
func NewArgon2Parameters(argon2Type, memory, iterations, lanes int, salt []byte) (*Argon2Parameters, error) {
	// Ensure valid type
	if argon2Type != Argon2d && argon2Type != Argon2i && argon2Type != Argon2id {
		return nil, errors.New("invalid Argon2 type")
	}

	// Set up Argon2 parameters
	return &Argon2Parameters{
		Type:       argon2Type,
		Version:    19, // Argon2 version
		Memory:     memory,
		Iterations: iterations,
		Lanes:      lanes,
		Salt:       salt,
	}, nil
}

// Constants for Argon2 types
const (
	Argon2d = iota
	Argon2i
	Argon2id
)

// Argon2Hash holds the hash and its parameters.
type Argon2Hash struct {
	Hash       []byte
	Parameters *Argon2Parameters
}

// Encode encodes a raw Argon2 hash and its parameters into the standard Argon2-hash-string.
func Encode(hash []byte, parameters *Argon2Parameters) (string, error) {
	var builder strings.Builder

	var typePrefix string
	switch parameters.Type {
	case Argon2d:
		typePrefix = "$argon2d"
	case Argon2i:
		typePrefix = "$argon2i"
	case Argon2id:
		typePrefix = "$argon2id"
	default:
		return "", fmt.Errorf("invalid algorithm type: %d", parameters.Type)
	}

	builder.WriteString(typePrefix)
	builder.WriteString(fmt.Sprintf("$v=%d$m=%d,t=%d,p=%d", parameters.Version, parameters.Memory, parameters.Iterations, parameters.Lanes))

	if parameters.Salt != nil {
		builder.WriteString("$" + base64.RawStdEncoding.EncodeToString(parameters.Salt))
	}
	builder.WriteString("$" + base64.RawStdEncoding.EncodeToString(hash))

	return builder.String(), nil
}

// Decode decodes an Argon2 hash string into the raw hash and the used parameters.
func Decode(encodedHash string) (*Argon2Hash, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) < 5 {
		return nil, errors.New("invalid encoded Argon2-hash")
	}

	var params Argon2Parameters
	var err error

	switch parts[1] {
	case "argon2d":
		params.Type = Argon2d
	case "argon2i":
		params.Type = Argon2i
	case "argon2id":
		params.Type = Argon2id
	default:
		return nil, fmt.Errorf("invalid algorithm type: %s", parts[1])
	}

	if strings.HasPrefix(parts[2], "v=") {
		fmt.Sscanf(parts[2][2:], "%d", &params.Version)
	}

	performanceParams := strings.Split(parts[3], ",")
	if len(performanceParams) != 3 {
		return nil, errors.New("amount of performance parameters invalid")
	}

	if !strings.HasPrefix(performanceParams[0], "m=") {
		return nil, errors.New("invalid memory parameter")
	}
	fmt.Sscanf(performanceParams[0][2:], "%d", &params.Memory)

	if !strings.HasPrefix(performanceParams[1], "t=") {
		return nil, errors.New("invalid iterations parameter")
	}
	fmt.Sscanf(performanceParams[1][2:], "%d", &params.Iterations)

	if !strings.HasPrefix(performanceParams[2], "p=") {
		return nil, errors.New("invalid parallelism parameter")
	}
	fmt.Sscanf(performanceParams[2][2:], "%d", &params.Lanes)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}
	params.Salt = salt

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, err
	}

	return &Argon2Hash{Hash: hash, Parameters: &params}, nil
}
