package filter

import (
	"log"
	"net/http"
)

func AuthFilterMiddleware(chain FilterChain, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := chain.DoFilter(r.Context(), r, w)

		if err != nil {
			log.Printf("Authentication failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
