package main

import (
	"errors"
	"fmt"
	"github.com/ayushs-2k4/go-security/Auth/filter"
	"net/http"
)

type JwtAuthenticationFilter struct{}

func (f *JwtAuthenticationFilter) DoFilter(req *http.Request, res http.ResponseWriter, chain filter.FilterChain) error {
	// JWT authentication logic
	token := req.Header.Get("Authorization")
	if token == "" {
		return errors.New("missing token")
	}

	// Continue the chain if authentication succeeds
	fmt.Println("JWT token authenticated")
	return chain.DoFilter(req, res)
}

type UsernamePasswordAuthFilter struct {
}

func (u UsernamePasswordAuthFilter) DoFilter(req *http.Request, res http.ResponseWriter, chain filter.FilterChain) error {
	// Username and password authentication logic
	username := req.Header.Get("username")
	password := req.Header.Get("password")
	if username == "" || password == "" {
		return errors.New("missing username or password")
	}

	if username == "admin" && password == "admin" {
		// Continue the chain if authentication succeeds
		fmt.Println("Username and password authenticated")
		return chain.DoFilter(req, res)
	}

	return errors.New("invalid credentials")
}

func main() {
	// Define the filters
	jwtFilter := &JwtAuthenticationFilter{}

	userpswrdFilter := &UsernamePasswordAuthFilter{}

	// Create the filter chain
	chain := filter.NewFilterChainImpl([]filter.AuthenticationFilter{jwtFilter, userpswrdFilter})

	// Add skip paths to the entire chain
	chain.AddSkipPaths("/public", "/health")

	// Example HTTP handler
	http.Handle("/", filter.AuthFilterMiddleware(chain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Request passed through filters"))
	})))

	http.ListenAndServe(":8080", nil)
}
