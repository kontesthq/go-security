package main

import (
	"fmt"
	"net/http"
)

func SecurityMiddleware(config *SecurityConfig, userDetailsService UserDetailsService, authenticationManager AuthenticationManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing myMiddleware Security")

		if matcher, exists := config.matchers[r.URL.Path]; exists {
			switch matcher.Access {
			case PermitAll:
				next.ServeHTTP(w, r)
				return

			case RoleRequired:
				usernamePasswordAuthenticationToken := NewUsernamePasswordAuthenticationToken("admin", "admin")

				user, err := authenticationManager.Authenticate(usernamePasswordAuthenticationToken)
				if err != nil {
					return
				}

				user.GetDetails()

				fmt.Println("RoleRequired")

			case DenyAll:
				http.Error(w, "Access Denied", http.StatusForbidden)
				fmt.Println("DenyAll")
				return

			default:
				http.Error(w, "Access Denied", http.StatusForbidden)
				fmt.Println("NoAccess")
				return
			}
		}

	})
}

func MyMiddleware1(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing myMiddleware 1")

		//http.Error(w, "Random number is less than 50", http.StatusInternalServerError)

		next.ServeHTTP(w, r)
	})
}

func MyMiddleware2(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing myMiddleware 2")

		// Do stuff here
		next.ServeHTTP(w, r)
	})
}
