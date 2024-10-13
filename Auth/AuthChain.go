package Auth

import (
	"errors"
	"log"
	"net/http"
)

type AuthChain struct {
	authMethods []AuthMethod
	skipPath    []string
}

func NewAuthChain(authMethods ...AuthMethod) *AuthChain {
	return &AuthChain{
		authMethods: authMethods,
		skipPath:    make([]string, 0),
	}
}

func (c *AuthChain) AddSkipPath(path string) {
	c.skipPath = append(c.skipPath, path)
}

func (c *AuthChain) authenticate(w http.ResponseWriter, r *http.Request) error {
	// Check if the request path is in the skip paths
	for _, skipPath := range c.skipPath {
		if r.URL.Path == skipPath {
			return nil // Skip authentication for this path
		}
	}

	havePassed := false

	for _, authMethod := range c.authMethods {
		ok, err := authMethod.Authenticate(w, r)

		if ok {
			havePassed = true
			break
		}
		if err != nil {
			log.Printf("Authentication failed in authMethod: %T, error: %v", authMethod, err)
		}
	}

	if havePassed {
		return nil // All authentication methods passed
	}

	return errors.New("authentication failed")

}

func AuthMiddleware(authChain *AuthChain, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := authChain.authenticate(w, r)

		if err != nil {
			log.Printf("Authentication failed: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
