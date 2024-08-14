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
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func assertErrorContains(t *testing.T, got error, want string) {
	t.Helper()
	if want == "" {
		assert.NoError(t, got)
	} else {
		assert.ErrorContains(t, got, want)
	}
}

type mockTransport struct {
	mock.Mock
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func requestTargetMatches(url string) any {
	return mock.MatchedBy(func(req *http.Request) bool {
		return req.URL.String() == url
	})
}

func httpResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type mockOpener struct {
	mock.Mock
}

func (m *mockOpener) Open(u *url.URL) error {
	args := m.Called(u)
	return args.Error(0)
}

func TestDeviceCode(t *testing.T) {
	testCases := []struct {
		desc               string
		browserOpenErr     error
		codeFetchResponse  *http.Response
		codeFetchErr       error
		tokenFetchResponse *http.Response
		tokenFetchErr      error

		wantToken *oauth2.Token
		wantErr   string
	}{
		{
			desc:               "successful auth",
			codeFetchResponse:  httpResponse(200, `{"device_code":"75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri_complete":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3\u0026userCode\u003dKLJQ-OQGG","user_code":"KLJQ-OQGG","expires_in":300,"interval":1}`),
			tokenFetchResponse: httpResponse(200, `{"access_token":"yippeekiyay","expires_in":7776000}`),
			wantToken: &oauth2.Token{
				AccessToken: "yippeekiyay",
			},
		},
		{
			desc:         "code fetch failure",
			codeFetchErr: errors.New("code_fetch_failure"),

			wantErr: "code_fetch_failure",
		},
		{
			desc:              "code fetch http error",
			codeFetchResponse: httpResponse(403, ``),

			wantErr: "oauth2: cannot fetch token",
		},
		{
			desc:              "browser open error",
			codeFetchResponse: httpResponse(200, `{"device_code":"75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri_complete":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3\u0026userCode\u003dKLJQ-OQGG","user_code":"KLJQ-OQGG","expires_in":300,"interval":1}`),
			browserOpenErr:    errors.New("browser_open_failure"),

			wantErr: "browser_open_failure",
		},
		{
			desc:              "token fetch failure",
			codeFetchResponse: httpResponse(200, `{"device_code":"75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri_complete":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3\u0026userCode\u003dKLJQ-OQGG","user_code":"KLJQ-OQGG","expires_in":300,"interval":1}`),
			tokenFetchErr:     errors.New("token_fetch_failure"),

			wantErr: "token_fetch_failure",
		},
		{
			desc:               "token fetch http error",
			codeFetchResponse:  httpResponse(200, `{"device_code":"75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3","verification_uri_complete":"https://oauth2.example.com/login?deviceCode\u003d75ba408f-fdf0-469a-a56e-b9a3a698f8b3\u0026userCode\u003dKLJQ-OQGG","user_code":"KLJQ-OQGG","expires_in":300,"interval":1}`),
			tokenFetchResponse: httpResponse(500, `internal server error`),

			wantErr: "oauth2: cannot fetch token",
		},
	}
	for _, tc := range testCases {
		testHost := &url.URL{Scheme: "https", Host: "oauth2.example.com"}
		deviceAuthEndpoint := "https://oauth2.example.com/api/v1/oauth2/device"
		tokenEndpoint := "https://oauth2.example.com/api/v1/oauth2/token"
		t.Run(tc.desc, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			opener := &mockOpener{}
			opener.On("Open", mock.Anything).Return(tc.browserOpenErr)

			transport := &mockTransport{}
			transport.On("RoundTrip", requestTargetMatches(deviceAuthEndpoint)).Return(tc.codeFetchResponse, tc.codeFetchErr)
			transport.On("RoundTrip", requestTargetMatches(tokenEndpoint)).Return(tc.tokenFetchResponse, tc.tokenFetchErr)

			deviceCode := &DeviceCode{
				browserOpener: opener,
				clientID:      "john_mcclane",
				scopes:        []string{"nypd", "lapd"},
				httpTransport: transport,
			}
			got, gotErr := deviceCode.Authenticate(ctx, testHost)

			assertErrorContains(t, gotErr, tc.wantErr)
			if gotErr != nil {
				return
			}

			got.Expiry = time.Time{}
			assert.EqualExportedValues(t, tc.wantToken, got)
		})
	}
}
