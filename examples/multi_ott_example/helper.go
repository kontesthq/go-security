package multi_ott_example

import (
	"github.com/ayushs-2k4/go-security/Auth"
	error2 "github.com/ayushs-2k4/go-security/Auth/error"
	"github.com/ayushs-2k4/go-security/internal/testing"
)

// Mock user data for demonstration
var userData = map[string]Auth.UserDetails{

	"testuser": &testing.TestUserPrincipal{User: testing.TestUser{
		Username: "testuser",
		Password: "password123", // Use a proper password (hashed) in a real app
		Leetcode: "testuserLeetcode",
	}},
}

func getUserDetails(username string) (Auth.UserDetails, error) {
	if user, exists := userData[username]; exists {
		return user, nil
	}

	return nil, &error2.UserNotFoundError{}
}
