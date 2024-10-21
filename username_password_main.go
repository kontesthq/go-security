package main

import (
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth"
	"github.com/ayushs-2k4/go-security/Auth/username_password"
	"log/slog"
)

type User struct {
	Username string
	Password string
	Leetcode string
}

type UserPrincipal struct {
	User User
}

func (u UserPrincipal) GetUsername() string {
	return u.User.Username
}

func (u UserPrincipal) GetPassword() string {
	return u.User.Password
}

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
				return UserPrincipal{
					User: User{
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

	isAuthenticated, err := usernamePasswordAuthenticationMethod.Authenticate()

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
