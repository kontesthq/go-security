package main

import (
	"bytes"
	"context"
	"github.com/kontesthq/go-security/Auth/filter"
	"github.com/kontesthq/go-security/Auth/ott"
	"github.com/kontesthq/go-security/Auth/request_matcher"
	"net/http"
	"net/url"
)

func main() {
	antPathRequestMatcher := *request_matcher.NewAntPathRequestMatcherWithPatternAndHttpMethodAndCaseSensitiveAndMatcher("/login/**", "GET", true)

	reqUrl, err := url.Parse("https://example.com/ott/generate?username=alice")
	if err != nil {
		panic(err)
	}

	httpReq := http.Request{
		Method: http.MethodPost,
		URL:    reqUrl,
	}

	matches := antPathRequestMatcher.Matches(&httpReq)

	if matches {
		println("Request matches")
	} else {
		println("Request does not match")
	}

	// Create a fake responseWriter
	response := &MockResponseWriter{
		header:     make(http.Header),
		statusCode: http.StatusOK, // default status code
	}

	generateOTTFilter := filter.NewGenerateOneTimeTokenFilter(ott.NewInMemoryOneTimeTokenService())
	generateOTTFilter.DoFilter(context.Background(), &httpReq, response, nil)
}

// MockResponseWriter is a struct that implements http.ResponseWriter for testing purposes.
type MockResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

// Header returns the header map that will be sent by the response.
func (m *MockResponseWriter) Header() http.Header {
	return m.header
}

// Write writes the data to the response body.
func (m *MockResponseWriter) Write(data []byte) (int, error) {
	return m.body.Write(data)
}

// WriteHeader sends an HTTP response header with the provided status code.
func (m *MockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

// GetBody returns the response body as a string for testing purposes.
func (m *MockResponseWriter) GetBody() string {
	return m.body.String()
}

// GetStatusCode returns the status code for testing purposes.
func (m *MockResponseWriter) GetStatusCode() int {
	return m.statusCode
}
