package main

import (
	"github.com/kontesthq/go-security/Auth/request_matcher"
	"net/http"
	"net/url"
)

func main() {
	antPathRequestMatcher := *request_matcher.NewAntPathRequestMatcherWithPatternAndHttpMethodAndCaseSensitiveAndMatcher("/login/**", "GET", true)

	reqUrl, err := url.Parse("https://example.com/login/admin")
	if err != nil {
		panic(err)
	}

	httpReq := http.Request{
		Method: "GET",
		URL:    reqUrl,
	}

	matches := antPathRequestMatcher.Matches(&httpReq)

	if matches {
		println("Request matches")
	} else {
		println("Request does not match")
	}
}
