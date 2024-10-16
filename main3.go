package main

import (
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth"
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
	DoAuthenticate("ayush", "ayush")
}

func DoAuthenticate(username string, password string) bool {
	usernamePasswordAuthenticationMethod := Auth.NewUsernamePasswordAuthenticationMethod(
		username,
		password,
		nil,
		true,
		func(username string) (Auth.UserDetails, error) {
			if username == "ayush" {
				if password == "ayush" {
					return UserPrincipal{
						User: User{
							Username: "ayush",
							Password: "ayush",
							Leetcode: "ayush",
						},
					}, nil
				} else {
					return nil, nil
				}
			}
			return nil, nil
		},
		func(username, newPassword string) error {
			fmt.Println("Changing password")
			return nil
		},
	)

	isAuthenticated, err := usernamePasswordAuthenticationMethod.Authenticate()

	if err != nil {
		return false
	}

	if isAuthenticated {
		fmt.Println("Authenticated")
	} else {
		fmt.Println("Not authenticated")
	}

	return isAuthenticated
}
