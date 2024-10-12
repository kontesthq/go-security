package main

import (
	"fmt"
	"net/http"
)

type SimpleAuthenticationManager struct {
}

func NewSimpleAuthenticationManager() *SimpleAuthenticationManager {
	return &SimpleAuthenticationManager{}
}

func (sam *SimpleAuthenticationManager) Authenticate(username string, password string) bool {
	if username == "admin" && password == "admin" {
		return true
	}

	return false
}

type SimpleUserDetailsService struct {
	// You can add a user store here (e.g., map or database connection)
	users map[string]User // Mock user store
}

func NewSimpleUserDetailsService() *SimpleUserDetailsService {
	return &SimpleUserDetailsService{
		users: map[string]User{
			"admin": {
				Username:              "admin",
				Password:              "password",
				Authorities:           []GrantedAuthority{},
				AccountNonExpired:     true,
				AccountNonLocked:      true,
				CredentialsNonExpired: true,
				Enabled:               true,
			},
		},
	}
}

// LoadUserByUsername loads a user by username.
func (suds *SimpleUserDetailsService) LoadUserByUsername(username string) (UserDetails, error) {
	user, exists := suds.users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

func main() {
	fmt.Println("Hello World")

	securityConfig := NewSecurityConfig()

	securityConfig.
		RequestMatchers("/hello").permitAll().
		RequestMatchers("/hello2").hasRole("admin").
		RequestMatchers("/hello3").denyAll()

	mux := http.NewServeMux()

	// Add middleware
	mux.HandleFunc("GET /hello", HelloGETHandler)
	mux.HandleFunc("GET /hello2", Hello2GETHandler)
	mux.HandleFunc("GET /hello3", Hello3GETHandler)
	mux.HandleFunc("POST /hello", HelloPOSTHandler)
	mux.HandleFunc("DELETE /hello", HelloDELETEHandler)
	mux.HandleFunc("PUT /hello", HelloPUTHandler)

	wrappedMux := SecurityMiddleware(securityConfig, NewSimpleUserDetailsService(), MyMiddleware1(MyMiddleware2(mux)))

	server := http.Server{
		Addr:    ":8080",
		Handler: wrappedMux,
	}

	fmt.Println("Server listening at applicationPort: 8080")

	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func HelloGETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World! GET")
}

func Hello2GETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello2, World! GET")
}

func Hello3GETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello3, World! GET")
}

func HelloPOSTHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World! POST")
}

func HelloPUTHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World! PUT")
}

func HelloDELETEHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World! DELETE")
}
