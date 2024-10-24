package request_matcher

import (
	"net/http"
)

// RequestMatcher defines an interface for matching HTTP requests.
type RequestMatcher interface {
	Matches(req *http.Request) bool
	Matcher(req *http.Request) MatchResult
}

// MatchResult represents the result of matching an HTTP request.
type MatchResult struct {
	Match     bool
	Variables map[string]string
}

// NewMatchResult creates a new MatchResult indicating a match.
func NewMatchResult(match bool, variables map[string]string) MatchResult {
	return MatchResult{
		Match:     match,
		Variables: variables,
	}
}

// Match creates a MatchResult that indicates a successful match with no variables.
func Match() MatchResult {
	return NewMatchResult(true, map[string]string{})
}

func MatchWithVariables(variables map[string]string) MatchResult {
	return NewMatchResult(true, variables)
}

// NotMatch creates a MatchResult that indicates no match.
func NotMatch() MatchResult {
	return NewMatchResult(false, map[string]string{})
}
