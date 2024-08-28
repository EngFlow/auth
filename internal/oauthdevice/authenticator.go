// Copyright 2024 EngFlow Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

const (
	codeChallengeMethodParamName = "code_challenge_method"
	codeChallengeMethodName      = "S256"
)

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
	// Use Golang's native version, but could probably use this approach for higher entropy
	// https://github.com/grafana/grafana/pull/80511/files
	verifier := oauth2.GenerateVerifier()
	codeChallenge := oauth2.VerifierOption(verifier)
	codeChallengeMethod := oauth2.SetAuthURLParam(codeChallengeMethodParamName, codeChallengeMethodName)

	res, err := a.config.DeviceAuth(ctx, codeChallenge, codeChallengeMethod)
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
