package oauthtoken

import (
	"context"

	"golang.org/x/oauth2"
)

type LoadStorer interface {
	Load(context.Context, string) (*oauth2.Token, error)
	Store(context.Context, string, *oauth2.Token) error
}
