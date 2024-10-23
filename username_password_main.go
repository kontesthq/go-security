package main

import (
	"fmt"
	"github.com/kontesthq/go-security/Auth"
	"github.com/kontesthq/go-security/Auth/username_password"
	"github.com/kontesthq/go-security/internal/testing"
	"log/slog"
)

func main() {
	DoAuthenticateUsernameEmail("ayush", "ayush")
}

func DoAuthenticateUsernameEmail(username string, password string) bool {
	usernamePasswordAuthenticationMethod := username_password.NewUsernamePasswordAuthenticationMethod(
		username,
		password,
		nil,
		true,
		func(username string) (Auth.UserDetails, error) {
			if username == "ayush" {
				return testing.TestUserPrincipal{
					User: testing.TestUser{
						Username: "ayush",
						Password: "{argon2}$argon2id$v=19$m=16384,t=2,p=1$V3srpAFTpAbEKK14Yonp/w$6r5fPPWocuvpM5XuLv5buh+ZA+aOaNIzAK0wGuWo0qA",
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

	isAuthenticated, _, err := usernamePasswordAuthenticationMethod.Authenticate()

	if err != nil {
		slog.Error("Error authenticating", slog.String("error", err.Error()))
		return false
	}

	if isAuthenticated {
		fmt.Println("Authenticated")
	} else {
		fmt.Println("Not authenticated")
	}

	return isAuthenticated
}
