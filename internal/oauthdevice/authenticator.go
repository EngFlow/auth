package oauthdevice

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/oauth2"
)

var errUnexpectedHTML = errors.New("request to JSON API returned HTML unexpectedly")

type Authenticator interface {
	FetchCode(context.Context, *oauth2.Endpoint) (*oauth2.DeviceAuthResponse, error)
	FetchToken(context.Context, *oauth2.DeviceAuthResponse) (*oauth2.Token, error)
}

type Auth struct {
	config *oauth2.Config
}

func NewAuth(clientID string, scopes []string) *Auth {
	return &Auth{
		config: &oauth2.Config{
			ClientID: clientID,
			Scopes:   scopes,
		},
	}
}

func (a *Auth) FetchCode(ctx context.Context, authEndpoint *oauth2.Endpoint) (*oauth2.DeviceAuthResponse, error) {
	a.config.Endpoint = *authEndpoint
	res, err := a.config.DeviceAuth(ctx)
	if err != nil {
		if oauthErr := (*oauth2.RetrieveError)(nil); errors.As(err, &oauthErr) {
			return nil, err
		}
		// BUG(CUS-320): Clusters that are not oauth-aware will return HTML with
		// a 2xx code, confusing the oauth library. Detect and alias those
		// errors here.
		if strings.Contains(err.Error(), "invalid character '<'") {
			return res, errUnexpectedHTML
		}
		// Default error handling
		return nil, err
	}
	return res, err
}

func (a *Auth) FetchToken(ctx context.Context, authRes *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	return a.config.DeviceAccessToken(ctx, authRes)
}
