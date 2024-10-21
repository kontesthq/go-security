package Auth

import (
	"errors"
	"log"
	"net/http"
	"regexp"
)

type AuthChain struct {
	authenticationProvider []AuthenticationProvider
	skipPaths              []*regexp.Regexp
}

func NewAuthChain(authMethods ...AuthenticationProvider) *AuthChain {
	return &AuthChain{
		authenticationProvider: authMethods,
		skipPaths:              make([]*regexp.Regexp, 0),
	}
}

// AddSkipPath allows adding regex patterns for paths that should skip authentication
func (c *AuthChain) AddSkipPath(path string) error {
	// convert to regex
	regexPath, err := regexp.Compile(path)

	if err != nil {
		return err
	}

	c.skipPaths = append(c.skipPaths, regexPath)
	return nil
}

// AddSkipPaths allows adding multiple regex patterns for paths that should skip authentication
func (c *AuthChain) AddSkipPaths(paths ...string) error {
	for _, regexPath := range paths {
		err := c.AddSkipPath(regexPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *AuthChain) authenticate(w http.ResponseWriter, r *http.Request) error {
	// Check if the request path is in the skip paths
	for _, skipPath := range c.skipPaths {
		if skipPath.MatchString(r.URL.Path) {
			return nil // Skip authentication for this path
		}
	}

	havePassed := false

	for _, authMethod := range c.authenticationProvider {
		ok, _, err := authMethod.Authenticate(w, r)

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
