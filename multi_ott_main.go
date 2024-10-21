package main

import (
	"fmt"
	"github.com/ayushs-2k4/go-security/examples/multi_ott_example"
	"log"
)

func main() {
	// Simulate the one-time token login flow

	// Create a new instance of the LoginOneTimeToken service
	ottLogin := multi_ott_example.NewLoginOneTimeToken()

	// Generate a one-time token for a user (e.g., "testuser")
	username := "testuser"
	token, err := ottLogin.GenerateToken(username)
	if err != nil {
		log.Fatalf("Error generating token: %v\n", err)
	}

	// Print the generated token value for the user
	generatedToken := token.GetTokenValue()
	fmt.Printf("Generated Token: %s\n", generatedToken)

	// Simulate user input by asking the user to provide the token string
	var providedToken string
	fmt.Println("Enter the provided token: ")
	// In a real application, you'd probably use fmt.Scanln(&providedToken)
	providedToken = generatedToken // For simulation, using the generated token directly

	// Use the provided token string for authentication
	authenticatedUsername, err := ottLogin.DoAuthenticateForgotPassword(providedToken)
	if err != nil {
		log.Fatalf("Authentication failed: %v\n", err)
	}

	fmt.Printf("Authenticated user: %s\n", authenticatedUsername)

	fmt.Println()
	// Now let's simulate the forgot password flow

	// Create a new instance of the ForgotPasswordOneTimeToken service
	ottForgotPassword := multi_ott_example.NewForgotPasswordOneTimeToken()

	// Generate a one-time token for forgot password
	forgotPasswordToken, err := ottForgotPassword.GenerateToken(username)
	if err != nil {
		log.Fatalf("Error generating forgot password token: %v\n", err)
	}

	// Print the generated forgot password token value
	forgotPasswordGeneratedToken := forgotPasswordToken.GetTokenValue()
	fmt.Printf("Forgot Password Generated Token: %s\n", forgotPasswordGeneratedToken)

	// Simulate user input for the forgot password token
	fmt.Println("Enter the provided forgot password token: ")
	// Simulate the input (in a real app, you would collect this from the user)
	providedForgotPasswordToken := forgotPasswordGeneratedToken // For simulation, using the generated token directly

	// Use the provided forgot password token string for authentication
	authenticatedForgotPasswordUsername, err := ottForgotPassword.DoAuthenticateForgotPassword(providedForgotPasswordToken)
	if err != nil {
		log.Fatalf("Forgot password authentication failed: %v\n", err)
	}

	fmt.Printf("Authenticated forgot password user: %s\n", authenticatedForgotPasswordUsername)
}
