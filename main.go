package main

import (
	"fmt"
	"go-security/internal/auth"
	"go-security/internal/auth/Store"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

func main() {
	email := "user@example.com"
	password := "password123"

	jwtSecret := "my_secret"
	tokenExpiry := 5 * time.Minute

	inMemoryUserStore := Store.NewInMemoryUserStore()
	inMemoryRefreshTokenStore := Store.NewInMemoryRefreshTokenStore()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	inMemoryUserStore.AddUser(email, string(hashedPassword))

	// Initialize the PasswordAuth method
	passwordAuth := auth.NewPasswordAuth(auth.AuthConfig{
		JwtSecret:   []byte(jwtSecret),
		TokenExpiry: tokenExpiry,
	}, inMemoryUserStore)

	// Authenticate the user
	isAuthenticated, err := passwordAuth.Authenticate(email, password)
	if err != nil || !isAuthenticated {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Generate JWT and Refresh Token
	jwtToken, refreshToken, err := auth.GenerateJWT(email, []byte(jwtSecret), tokenExpiry, inMemoryRefreshTokenStore)

	log.Printf("Generated JWT: %s\n, refresh Token: %s\n", jwtToken, refreshToken)

	fmt.Println()

	// Validate the JWT
	isValid, err := auth.ValidateJWT(jwtToken, []byte(jwtSecret))
	if err != nil || !isValid {
		log.Fatalf("Token validation failed: %v", err)
	}

	// Refreshing the JWT
	newJWTToken, newRefreshToken, err := auth.RefreshJWT(refreshToken, []byte(jwtSecret), inMemoryRefreshTokenStore)
	if err != nil {
		log.Fatalf("Failed to refresh JWT: %v", err)
	}

	log.Printf("Refreshed Generated JWT: %s\n, Refreshed refresh Token: %s\n", newJWTToken, newRefreshToken)

	fmt.Println()

	// Trying to use old Refresh token to get new JWT Token
	_, _, err = auth.RefreshJWT(refreshToken, []byte(jwtSecret), inMemoryRefreshTokenStore)

	if err != nil {
		log.Println("Cannot use old Refresh Token")
	} else {
		log.Fatalf("Old Refresh Token is valid!")
	}

	// Trying to use new Refresh Token
	newJWTToken, newRefreshToken, err = auth.RefreshJWT(newRefreshToken, []byte(jwtSecret), inMemoryRefreshTokenStore)

	if err != nil {
		log.Fatalf("Refresh Token validation failed: %v", err)
	}

	log.Println("Only new Refresh Token works!")

}
