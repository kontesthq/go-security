package main

import (
	"fmt"
	"github.com/ayushs-2k4/go-security/examples/multi_ott_example"
	"log"
)

func main() {
	// Create a new instance of the OneTimeTokenForgotPassword service
	ottForgotPassword := multi_ott_example.NewOneTimeTokenForgotPassword()

	// Generate a one-time token for a user (e.g., "testuser")
	username := "testuser"
	token, err := ottForgotPassword.GenerateToken(username)
	if err != nil {
		log.Fatalf("Error generating token: %v\n", err)
	}

	// Print the generated token value for the user
	generatedToken := token.GetTokenValue()
	fmt.Printf("Generated Token: %s\n", generatedToken)

	// Simulate user input by asking the user to provide the token string
	var providedToken string
	fmt.Print("Enter the provided token: ")
	//fmt.Scanln(&providedToken)
	providedToken = generatedToken

	// Use the provided token string for authentication
	authenticatedUsername, err := ottForgotPassword.DoAuthenticateForgotPassword(providedToken)
	if err != nil {
		log.Fatalf("Authentication failed: %v\n", err)
	}

	fmt.Printf("Authenticated user: %s\n", authenticatedUsername)
}
