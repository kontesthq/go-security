package ott

import "errors"

type GenerateOneTimeTokenRequest struct {
	Username string
}

func NewGenerateOneTimeTokenRequest(username string) (*GenerateOneTimeTokenRequest, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	return &GenerateOneTimeTokenRequest{Username: username}, nil
}

func (g *GenerateOneTimeTokenRequest) GetUsername() string {
	return g.Username
}
