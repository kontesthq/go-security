package filter

import (
	"context"
	"github.com/kontesthq/go-security/Auth/ott"
	"github.com/kontesthq/go-security/Auth/request_matcher"
	"net/http"
)

type GenerateOneTimeTokenFilter struct {
	oneTimeTokenService          ott.OneTimeTokenService
	requestMatcher               request_matcher.RequestMatcher
	generatedOneTimeTokenHandler ott.GeneratedOneTimeTokenHandler
}

func NewGenerateOneTimeTokenFilter(oneTimeTokenService ott.OneTimeTokenService) *GenerateOneTimeTokenFilter {
	return &GenerateOneTimeTokenFilter{
		oneTimeTokenService:          oneTimeTokenService,
		requestMatcher:               request_matcher.NewAntPathRequestMatcherWithPatternAndHttpMethod("/ott/generate", http.MethodPost),
		generatedOneTimeTokenHandler: ott.NewRedirectGeneratedOneTimeTokenHandler("/login/ott"),
	}
}

func (g *GenerateOneTimeTokenFilter) DoFilter(ctx context.Context, req *http.Request, res http.ResponseWriter, chain FilterChain) error {
	if !g.requestMatcher.Matches(req) {
		chain.DoFilter(ctx, req, res)
		return nil
	}

	username := req.URL.Query().Get("username")
	if username == "" {
		chain.DoFilter(ctx, req, res)
		return nil
	}

	generateRequest, _ := ott.NewGenerateOneTimeTokenRequest(username)
	oneTimeToken := g.oneTimeTokenService.Generate(*generateRequest)
	g.generatedOneTimeTokenHandler.Handle(req, res, oneTimeToken)

	return nil
}

func (g *GenerateOneTimeTokenFilter) SetRequestMatcher(requestMatcher request_matcher.RequestMatcher) {
	if requestMatcher == nil {
		panic("requestMatcher cannot be nil")
	}

	g.requestMatcher = requestMatcher
}

func (g *GenerateOneTimeTokenFilter) SetGeneratedOneTimeTokenHandler(generatedOneTimeTokenHandler ott.GeneratedOneTimeTokenHandler) {
	g.generatedOneTimeTokenHandler = generatedOneTimeTokenHandler
}
