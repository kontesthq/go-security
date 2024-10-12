package Auth

import (
	"errors"
	"github.com/ayushs-2k4/go-security/Auth/Store"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"log"
	"time"
)

type Claim struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func GenerateJWT(subject string, secret []byte, expiry time.Duration, refreshTokenStore Store.RefreshTokenStore) (string, string, error) {
	// Generate JWT
	jwtToken, err := generateJWTOnly(subject, secret, expiry)
	if err != nil {
		return "", "", err
	}

	// Generate Refresh Token
	refreshToken, err := GenerateRefreshToken(subject, refreshTokenStore)
	if err != nil {
		return "", "", err
	}

	return jwtToken, refreshToken, nil
}

func generateJWTOnly(subject string, secret []byte, expiry time.Duration) (string, error) {
	expirationTime := time.Now().Add(expiry)

	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   subject,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateJWT(tokenString string, secret []byte) (bool, error) {
	claims := &Claim{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil || !token.Valid {
		return false, err
	}

	return true, nil
}

// GenerateRefreshToken generates a simple UUID as a refresh token.
func GenerateRefreshToken(subject string, refreshTokenStore Store.RefreshTokenStore) (string, error) {
	// Generate a new UUID for the refresh token
	refreshToken := uuid.New().String()

	// Store the refresh token along with the associated subject
	err := refreshTokenStore.Save(refreshToken, subject)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func RefreshJWT(refreshTokenString string, secret []byte, refreshTokenStore Store.RefreshTokenStore) (string, string, error) {
	// Validate refresh token
	username, err := refreshTokenStore.FindSubject(refreshTokenString)
	if err != nil {
		return "", "", errors.New("invalid refresh token")
	}

	// Generate new JWT
	newJWT, err := generateJWTOnly(username, secret, time.Hour*72) // Adjust the expiry time as needed
	if err != nil {
		return "", "", err // Propagate the error if JWT generation fails
	}

	// Generate a new refresh token
	newRefreshToken, err := GenerateRefreshToken(username, refreshTokenStore)
	if err != nil {
		return "", "", err // Propagate the error if refresh token generation fails
	}

	invalidateOldRefreshToken(refreshTokenString, refreshTokenStore) // Invalidate the old refresh token

	return newJWT, newRefreshToken, nil // Return both tokens
}

func invalidateOldRefreshToken(refreshToken string, refreshTokenStore Store.RefreshTokenStore) {
	err := refreshTokenStore.Delete(refreshToken)
	if err != nil {
		log.Println("Failed to delete old refresh token")
		return
	}
}
