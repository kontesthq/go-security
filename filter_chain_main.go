package main

import (
	"context"
	"fmt"
	"github.com/kontesthq/go-security/Auth/filter"
	"github.com/kontesthq/go-security/Auth/security"
	"net/http"
)

type TestFilter2Authentication struct {
	// Fields to hold authentication details
	Authenticated bool
}

func (t *TestFilter2Authentication) GetCredentials() interface{} {
	// Return credentials (could be a username, password, etc.)
	return nil // Adjust as needed
}

func (t *TestFilter2Authentication) GetDetails() interface{} {
	// Return additional details about the authentication
	return nil // Adjust as needed
}

func (t *TestFilter2Authentication) GetPrincipal() interface{} {
	// Return the principal (user) of the authentication
	return nil // Adjust as needed
}

func (t *TestFilter2Authentication) IsAuthenticated() bool {
	return t.Authenticated
}

func (t *TestFilter2Authentication) SetAuthenticated(isAuthenticated bool) error {
	t.Authenticated = isAuthenticated
	return nil
}

type TestFilter1 struct {
}

func (t *TestFilter1) DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter, chain filter.FilterChain) error {
	// Log a message indicating that TestFilter1 is processing the request
	fmt.Println("TestFilter1: Processing request")

	// Proceed to the next filter in the chain
	return chain.DoFilter(ctx, req, res)
}

type TestFilter2 struct {
}

func (t *TestFilter2) DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter, chain filter.FilterChain) error {
	// Check for a specific header in the request
	if req.Header.Get("X-Custom-Header") == "" {
		// If the header is not present, respond with an error
		return chain.DoFilter(ctx, req, res) // Continue the filter chain
	}

	securityContext := *security.GetSecurityContextHolder().GetSecurityContext(ctx)

	// Create an instance of TestFilter2Authentication
	auth := &TestFilter2Authentication{Authenticated: true} // Set to true for demo

	// Set the authentication in the security context
	if err := securityContext.SetAuthentication(auth); err != nil {
		return err
	}

	// Log a message indicating that TestFilter2 is processing the request
	fmt.Println("TestFilter2: Header found, processing request")

	// Proceed to the next filter in the chain
	return chain.DoFilter(ctx, req, res)
}

func main() {

	//holder := security.GetSecurityContextHolder()
	//fmt.Println(holder)

	filterChain := filter.NewFilterChainImpl([]filter.AuthenticationFilter{&TestFilter1{}, &TestFilter2{}})

	http.Handle("/", filter.AuthFilterMiddleware(filterChain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Request passed through filters"))
	})))

	fmt.Println("Listening at 8080")

	http.ListenAndServe(":8080", nil)
}
