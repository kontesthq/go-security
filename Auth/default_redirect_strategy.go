package Auth

import (
	"log/slog"
	"net/http"
	"strings"
)

type DefaultRedirectStrategy struct {
	contextRelative bool
	statusCode      int // HTTP status code
}

func NewDefaultRedirectStrategy() *DefaultRedirectStrategy {
	return &DefaultRedirectStrategy{
		statusCode: http.StatusFound, // Default status code is 302 (FOUND)
	}
}

// extractContextPath extracts the context path from the request URL path.
func extractContextPath(requestPath string) string {
	// Split the request path and return the base context path
	segments := strings.Split(requestPath, "/")
	return segments[0]
}

func (s *DefaultRedirectStrategy) SendRedirect(request *http.Request, response http.ResponseWriter, url string) error {
	contextPath := extractContextPath(request.URL.Path)
	redirectURL := s.calculateRedirectURL(contextPath, url)

	if s.statusCode == http.StatusFound {
		slog.Debug("Redirecting to %s", redirectURL)
		http.Redirect(response, request, redirectURL, s.statusCode)
		return nil
	} else {
		response.Header().Set("Location", redirectURL)
		response.WriteHeader(s.statusCode)
		_, err := response.Write([]byte{})
		return err
	}
}

// calculateRedirectURL calculates the redirect URL based on the context path and the provided URL.
func (s *DefaultRedirectStrategy) calculateRedirectURL(contextPath, url string) string {
	if !isAbsoluteURL(url) {
		if s.isContextRelative() {
			return url
		}
		return contextPath + url
	}
	// Full URL, including http(s)://
	if !s.isContextRelative() {
		return url
	}
	if !strings.Contains(url, contextPath) {
		panic("The fully qualified URL does not include context path.")
	}
	// Calculate the relative URL from the fully qualified URL, minus the last
	// occurrence of the scheme and base context.
	url = strings.TrimPrefix(url[strings.Index(url, "://")+3:], contextPath)
	if len(url) > 0 && url[0] == '/' {
		url = url[1:] // Remove leading slash
	}
	return url
}

// SetContextRelative sets whether to calculate redirection URLs minus the protocol and context path.
func (s *DefaultRedirectStrategy) SetContextRelative(useRelativeContext bool) {
	s.contextRelative = useRelativeContext
}

// isContextRelative returns true if redirection URLs should be calculated minus the protocol and context path.
func (s *DefaultRedirectStrategy) isContextRelative() bool {
	return s.contextRelative
}

// SetStatusCode sets the HTTP status code to use.
func (s *DefaultRedirectStrategy) SetStatusCode(statusCode int) {
	if statusCode < 100 || statusCode > 599 {
		panic("statusCode must be a valid HTTP status code")
	}
	s.statusCode = statusCode
}

// isAbsoluteURL checks if the URL is absolute.
func isAbsoluteURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}
