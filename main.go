package main

import (
	Auth "github.com/ayushs-2k4/go-security/Auth"
	Store2 "github.com/ayushs-2k4/go-security/Auth/Store"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

func main() {
	email := "user@example.com"
	password := "password123"

	jwtSecret := "my_secret"
	tokenExpiry := 5 * time.Minute

	inMemoryUserStore := Store2.NewInMemoryUserStore()
	//inMemoryRefreshTokenStore := Store2.NewInMemoryRefreshTokenStore()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	inMemoryUserStore.AddUser(email, string(hashedPassword))

	// Initialize the PasswordAuth method
	passwordAuth := Auth.NewPasswordAuth(Auth.AuthConfig{
		JwtSecret:   []byte(jwtSecret),
		TokenExpiry: tokenExpiry,
	}, inMemoryUserStore)

	authChain := Auth.NewAuthChain(passwordAuth)

	router := http.NewServeMux()
	router.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	wrappedWouter := Auth.AuthMiddleware(authChain, router)

	err = http.ListenAndServe(":8080", wrappedWouter)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	////isAuthenticated, err := passwordAuth.authenticate(email, password)
	//if err != nil {
	//	log.Fatalf("Authentication failed: %v", err)
	//} else {
	//	log.Println("Authentication successful")
	//}
	//
	//// Generate JWT and Refresh Token
	//jwtToken, refreshToken, err := Auth.GenerateJWT(email, []byte(jwtSecret), tokenExpiry, inMemoryRefreshTokenStore)
	//
	//log.Printf("Generated JWT: %s\n, refresh Token: %s\n", jwtToken, refreshToken)
	//
	//fmt.Println()
	//
	//// Validate the JWT
	//isValid, err := Auth.ValidateJWT(jwtToken, []byte(jwtSecret))
	//if err != nil || !isValid {
	//	log.Fatalf("Token validation failed: %v", err)
	//}
	//
	//// Refreshing the JWT
	//newJWTToken, newRefreshToken, err := Auth.RefreshJWT(refreshToken, []byte(jwtSecret), inMemoryRefreshTokenStore)
	//if err != nil {
	//	log.Fatalf("Failed to refresh JWT: %v", err)
	//}
	//
	//log.Printf("Refreshed Generated JWT: %s\n, Refreshed refresh Token: %s\n", newJWTToken, newRefreshToken)
	//
	//fmt.Println()
	//
	//// Trying to use old Refresh token to get new JWT Token
	//_, _, err = Auth.RefreshJWT(refreshToken, []byte(jwtSecret), inMemoryRefreshTokenStore)
	//
	//if err != nil {
	//	log.Println("Cannot use old Refresh Token")
	//} else {
	//	log.Fatalf("Old Refresh Token is valid!")
	//}
	//
	//// Trying to use new Refresh Token
	//newJWTToken, newRefreshToken, err = Auth.RefreshJWT(newRefreshToken, []byte(jwtSecret), inMemoryRefreshTokenStore)
	//
	//if err != nil {
	//	log.Fatalf("Refresh Token validation failed: %v", err)
	//}
	//
	//log.Println("Only new Refresh Token works!")

}
