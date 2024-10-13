package main

import (
	"encoding/json"
	"github.com/ayushs-2k4/go-security/Auth"
	"github.com/ayushs-2k4/go-security/Auth/Store"
	"github.com/ayushs-2k4/go-security/internal/Testing"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

func getInMemoryUserStore() *Store.InMemoryUserStore {
	email := "user@example.com"
	password := "password123"

	inMemoryUserStore := Store.NewInMemoryUserStore()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	inMemoryUserStore.AddUser(email, string(hashedPassword))

	return inMemoryUserStore
}

func main() {

	jwtSecret := "my_secret"

	inMemoryUserStore := getInMemoryUserStore()

	// Initialize the PasswordAuth method
	usernamePasswordAuth := Auth.NewPasswordAuth(inMemoryUserStore)

	jwtAuth := Auth.NewJWTAuth([]byte(jwtSecret))

	authChain := Auth.NewAuthChain(jwtAuth, usernamePasswordAuth)

	// Add a skip path
	authChain.AddSkipPath("^/login(/.*)?$")

	router := http.NewServeMux()
	router.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// Wrap the router with the AuthMiddleware
	router.HandleFunc("PUT /login", HandleLogin)

	wrappedWouter := Auth.AuthMiddleware(authChain, router)

	err := http.ListenAndServe(":8080", wrappedWouter)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}

}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	jwtSecret := "my_secret"
	tokenExpiry := 10 * time.Second

	inMemoryUserStore := getInMemoryUserStore()

	var loginReq Testing.LoginRequest

	// Decode the JSON request body
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Now you can access username and password
	username := loginReq.Username
	password := loginReq.Password

	user, err := inMemoryUserStore.FindUserByUsername(username)

	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Password check (in a real scenario, you'd retrieve the hash from a DB)
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Error(w, "Wrong Username password", http.StatusForbidden)
		return
	}

	// Authentication successful
	jwtToken, refreshToken, err := Auth.GenerateJWT(username, []byte(jwtSecret), tokenExpiry, Store.NewInMemoryRefreshTokenStore())

	jWTResponse := JWTResponse{
		JWTToken:     jwtToken,
		RefreshToken: refreshToken,
	}

	// Set content type and status code
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // Set the status code explicitly

	// Marshal the response to JSON
	responseBody, err := json.Marshal(jWTResponse)
	if err != nil {
		http.Error(w, "Failed to create response", http.StatusInternalServerError)
		return
	}

	// Send the JSON response
	_, err = w.Write(responseBody) // Write the marshalled JSON response to the ResponseWriter
	if err != nil {
		http.Error(w, "Failed to send response", http.StatusInternalServerError)
		return
	}
}

type JWTResponse struct {
	JWTToken     string `json:"jwtToken"`
	RefreshToken string `json:"refreshToken"`
}
