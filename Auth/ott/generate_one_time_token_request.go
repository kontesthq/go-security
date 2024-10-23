package ott

import (
	error2 "github.com/kontesthq/go-security/Auth/error"
)

type GenerateOneTimeTokenRequest struct {
	Username string
}

func NewGenerateOneTimeTokenRequest(username string) (*GenerateOneTimeTokenRequest, error) {
	if username == "" {
		return nil, &error2.UsernameEmptyError{}
	}

	return &GenerateOneTimeTokenRequest{Username: username}, nil
}

func (g *GenerateOneTimeTokenRequest) GetUsername() string {
	return g.Username
}
