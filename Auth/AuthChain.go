package Auth

import (
	"log"
	"net/http"
)

type AuthChain struct {
	authMethods []AuthMethod
}

func NewAuthChain(authMethods ...AuthMethod) *AuthChain {
	return &AuthChain{authMethods: authMethods}
}

func (c *AuthChain) authenticate(w http.ResponseWriter, r *http.Request) error {
	for _, authMethod := range c.authMethods {
		ok, err := authMethod.Authenticate(w, r)

		if ok {
			continue
		}
		if err != nil {
			log.Printf("Authentication failed in authMethod: %T, error: %v", authMethod, err)

			return err
		}
	}

	return nil
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
