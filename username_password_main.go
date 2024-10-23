package main

import (
	"fmt"
	"github.com/kontesthq/go-security/Auth"
	"github.com/kontesthq/go-security/Auth/username_password"
	"github.com/kontesthq/go-security/internal/testing"
	"log/slog"
)

func main() {
	DoAuthenticateUsernameEmail("ayush", "ayush_pswrd")
}

func DoAuthenticateUsernameEmail(username string, password string) bool {
	usernamePasswordAuthenticationMethod := username_password.NewUsernamePasswordAuthenticationProvider(
		nil,
		true,
		func(username string) (Auth.UserDetails, error) {
			if username == "ayush" {
				return testing.TestUserPrincipal{
					User: testing.TestUser{
						Username: "ayush",
						Password: "ayush_pswrd",
						Leetcode: "ayush",
					},
				}, nil

			} else {
				return nil, nil
			}
		},
		func(username, newPassword string) error {
			fmt.Println("Changing password to: " + newPassword)
			return nil
		},
	)

	UsernamePToken := username_password.NewUsernamePasswordAuthenticationToken(username, password)

	authentication, err := usernamePasswordAuthenticationMethod.Authenticate(UsernamePToken)

	if err != nil {
		slog.Error("Error authenticating", slog.String("error", err.Error()))
		return false
	}

	if authentication.IsAuthenticated() {
		fmt.Println("Authenticated")
	} else {
		fmt.Println("Not authenticated")
	}

	return authentication.IsAuthenticated()
}
