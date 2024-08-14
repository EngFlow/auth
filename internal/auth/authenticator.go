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

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/EngFlow/auth/internal/autherr"
	"github.com/EngFlow/auth/internal/browser"
)

var errUnexpectedHTML = errors.New("request to JSON API returned HTML unexpectedly")

// Backend implementations specify the entire authentication flow to obtain an
// OAuth2 token given a backend endpoint.
type Backend interface {
	// Authenticate returns a valid token for the specified endpoint.
	Authenticate(ctx context.Context, host *url.URL) (*oauth2.Token, error)
}

// DeviceCode implements Backend via the "OAuth2 device flow", which involves:
// * obtaining an ephemeral device code
// * instructing the user to log in via a browser, and enter the device code
// * polling the server for completion, and fetching the generated token
type DeviceCode struct {
	browserOpener browser.Opener
	clientID      string
	scopes        []string
	// httpTransport sets the behavior of HTTP calls under unit tests; it is
	// intentionally unexported so that only package-level tests can hook HTTP
	// calls.
	httpTransport http.RoundTripper
}

func NewDeviceCode(browserOpener browser.Opener, clientID string, scopes []string) *DeviceCode {
	return &DeviceCode{
		browserOpener: browserOpener,
		clientID:      clientID,
		scopes:        scopes,
		// Explicitly leave this unset, to ensure the default HTTP transport is
		// used in non-test usecases.
		httpTransport: nil,
	}
}

func (d *DeviceCode) Authenticate(ctx context.Context, host *url.URL) (*oauth2.Token, error) {
	// Under tests, the HTTP transport might be set in order to stub out network
	// calls. If this is the case, ensure the oauth2 library is using it; the
	// library API around this is that it discovers a client via the context, or
	// uses some default if none is set (currently http.DefaultTransport).
	if d.httpTransport != nil {
		client := &http.Client{
			Transport: d.httpTransport,
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}

	config := &oauth2.Config{
		ClientID: d.clientID,
		Scopes:   d.scopes,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: urlWithPath(host, "api/v1/oauth2/device").String(),
			TokenURL:      urlWithPath(host, "api/v1/oauth2/token").String(),
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}
	res, err := config.DeviceAuth(ctx)
	if err != nil {
		if oauthErr := (*oauth2.RetrieveError)(nil); errors.As(err, &oauthErr) {
			return nil, err
		}
		// BUG(CUS-320): Older versions of engflow backends sometimes respond to
		// requests with HTTP 200 and an HTML body, which confuses the oauth2
		// library. This shouldn't happen anymore (newer versions return a 404
		// when oauth2 is not supported) but we still guard against it until no
		// old versions of backends are running anywhere.
		if strings.Contains(err.Error(), "invalid character '<'") {
			return nil, errUnexpectedHTML
		}
		// Default error handling
		return nil, err
	}

	// The "complete" URI that includes the device code pre-populated is ideal,
	// but technically optional. Prefer it, but fall back to the required URL in
	// the response if necessary.
	verificationURLStr := res.VerificationURIComplete
	if verificationURLStr == "" {
		verificationURLStr = res.VerificationURI
	}
	verificationURL, err := url.Parse(verificationURLStr)
	if err != nil {
		return nil, autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to parse authentication URL: %w", err)
	}
	if err := d.browserOpener.Open(verificationURL); err != nil {
		return nil, autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to open browser to perform authentication: %w", err)
	}

	return config.DeviceAccessToken(ctx, res)
}

func urlWithPath(u *url.URL, path string) *url.URL {
	newURL := &url.URL{}
	*newURL = *u
	newURL.Path = path
	return newURL
}
