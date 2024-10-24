package request_matcher

import (
	"github.com/vibrantbyte/go-antpath/antpath"
	"net/http"
	"strings"
)

const (
	MATCH_ALL = "/**"
)

type AntPathRequestMatcher struct {
	pattern       string
	httpMethod    string
	caseSensitive bool
	matcher       Matcher
}

// NewAntPathRequestMatcher creates a matcher with the specific pattern which will match all HTTP methods in a case-sensitive manner.
func NewAntPathRequestMatcher(pattern string) *AntPathRequestMatcher {
	if pattern == "" {
		panic("pattern cannot be empty")
	}

	return &AntPathRequestMatcher{
		pattern:       pattern,
		httpMethod:    "",
		caseSensitive: true,
	}
}

// NewAntPathRequestMatcherWithHttpMethod creates a matcher HTTP method which will match all HTTP methods in a case-sensitive manner.
func NewAntPathRequestMatcherWithHttpMethod(httpMethod string) *AntPathRequestMatcher {
	if httpMethod == "" {
		panic("httpMethod cannot be empty")
	}

	return &AntPathRequestMatcher{
		pattern:       "",
		httpMethod:    httpMethod,
		caseSensitive: true,
	}
}

// NewAntPathRequestMatcherWithPatternAndHttpMethod creates a matcher with the specific pattern and HTTP method in a case-sensitive manner.
func NewAntPathRequestMatcherWithPatternAndHttpMethod(pattern string, httpMethod string) *AntPathRequestMatcher {
	if pattern == "" {
		panic("pattern cannot be empty")
	}

	if httpMethod == "" {
		panic("httpMethod cannot be empty")
	}

	return &AntPathRequestMatcher{
		pattern:       pattern,
		httpMethod:    httpMethod,
		caseSensitive: true,
	}
}

// NewAntPathRequestMatcherWithPatternAndHttpMethodAndCaseSensitive creates a matcher with the specific pattern, HTTP method and case sensitivity.
func NewAntPathRequestMatcherWithPatternAndHttpMethodAndCaseSensitive(pattern string, httpMethod string, caseSensitive bool) *AntPathRequestMatcher {
	if pattern == "" {
		panic("pattern cannot be empty")
	}

	if httpMethod == "" {
		panic("httpMethod cannot be empty")
	}

	return &AntPathRequestMatcher{
		pattern:       pattern,
		httpMethod:    httpMethod,
		caseSensitive: caseSensitive,
	}
}

// NewAntPathRequestMatcherWithPatternAndHttpMethodAndCaseSensitiveAndMatcher creates a matcher with the specific pattern, HTTP method, case sensitivity and matcher.
func NewAntPathRequestMatcherWithPatternAndHttpMethodAndCaseSensitiveAndMatcher(pattern string, httpMethod string, caseSensitive bool) *AntPathRequestMatcher {
	if pattern == "" {
		panic("pattern cannot be empty")
	}

	if pattern == MATCH_ALL || pattern == "**" {
		pattern = MATCH_ALL

		return &AntPathRequestMatcher{
			pattern:       pattern,
			httpMethod:    httpMethod,
			caseSensitive: caseSensitive,
			matcher:       nil,
		}
	} else {
		var matcher Matcher

		if strings.HasSuffix(pattern, MATCH_ALL) && strings.IndexAny(pattern, "?{}") == -1 && strings.Index(pattern, "*") == len(pattern)-2 {
			matcher = NewSubpathMatcher(pattern[:len(pattern)-3], caseSensitive)
		} else {
			matcher = NewSpringAntMatcher(pattern, caseSensitive)
		}

		return &AntPathRequestMatcher{
			pattern:       pattern,
			httpMethod:    httpMethod,
			caseSensitive: caseSensitive,
			matcher:       matcher,
		}
	}
}

func (a AntPathRequestMatcher) Matches(req *http.Request) bool {
	if (req.Method != "") && (a.httpMethod != req.Method) {
		return false
	}

	if a.pattern == MATCH_ALL {
		return true
	}

	if a.matcher == nil {
		return false
	}

	url := req.URL.Path
	return a.matcher.matches(url)

}

func (a AntPathRequestMatcher) Matcher(req *http.Request) MatchResult {
	if !a.Matches(req) {
		return NotMatch()
	}

	if a.matcher == nil {
		return Match()
	}

	url := req.URL.Path
	return MatchWithVariables(a.matcher.extractUriTemplateVariables(url))
}

// Matcher interface defines methods for matching paths and extracting variables
type Matcher interface {
	matches(path string) bool
	extractUriTemplateVariables(path string) map[string]string
}

type SubpathMatcher struct {
	subpath       string
	length        int
	caseSensitive bool
}

func (s *SubpathMatcher) matches(path string) bool {
	if !s.caseSensitive {
		path = strings.ToLower(path)
	}

	// Check if path starts with subpath and either matches the length or has '/' at the right position
	return strings.HasPrefix(path, s.subpath) && (len(path) == s.length || (len(path) > s.length && path[s.length] == '/'))
}

func (s *SubpathMatcher) extractUriTemplateVariables(path string) map[string]string {
	return map[string]string{}
}

func NewSubpathMatcher(subpath string, caseSensitive bool) *SubpathMatcher {
	if strings.Contains(subpath, "*") {
		panic("subpath cannot contain the '*' character")
	}

	// Convert subpath to lowercase if not case-sensitive
	if !caseSensitive {
		subpath = strings.ToLower(subpath)
	}

	return &SubpathMatcher{
		subpath:       subpath,
		length:        len(subpath),
		caseSensitive: caseSensitive,
	}
}

type SpringAntMatcher struct {
	pattern    string
	antMatcher antpath.PathMatcher
}

func NewSpringAntMatcher(pattern string, caseSensitive bool) *SpringAntMatcher {
	antMatcher := antpath.New()
	antMatcher.SetCaseSensitive(caseSensitive)
	antMatcher.SetTrimTokens(false)

	return &SpringAntMatcher{
		pattern:    pattern,
		antMatcher: antMatcher,
	}
}

func (s *SpringAntMatcher) matches(path string) bool {
	return s.antMatcher.Match(s.pattern, path)
}

func (s *SpringAntMatcher) extractUriTemplateVariables(path string) map[string]string {
	return *s.antMatcher.ExtractUriTemplateVariables(s.pattern, path)
}
