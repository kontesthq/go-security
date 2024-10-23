package main

import (
	"fmt"
	"github.com/kontesthq/go-security/Auth/PasswordEncoder"
)

// Example usage (implementations of PasswordEncoder needed for real usage).
func main() {
	// Example usage
	idForEncode := "bcrypt"

	encoder, err := PasswordEncoder.NewDelegatingPasswordEncoder(idForEncode, PasswordEncoder.GetPasswordEncoders())
	if err != nil {
		fmt.Println("Error creating DelegatingPasswordEncoder:", err)
		return
	}

	rawPassword := "password"
	encoded, err := encoder.Encode(rawPassword)
	fmt.Println("Encoded password:", encoded)

	match, err := encoder.Matches(rawPassword, encoded)
	fmt.Println("Password matches:", match)
}
