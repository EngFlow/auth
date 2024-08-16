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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/EngFlow/auth/internal/autherr"
	"github.com/EngFlow/auth/internal/browser"
	"github.com/EngFlow/auth/internal/oauthdevice"
	"github.com/EngFlow/auth/internal/oauthtoken"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func codedErrorContains(t *testing.T, gotErr error, code int, wantMsg string) bool {
	t.Helper()
	// Handle cases where expecting an error but getting none, or vice versa
	if code == 0 && wantMsg == "" {
		if gotErr != nil {
			assert.Fail(
				t,
				"codedError validation failure",
				"want no error; got error: %v",
				gotErr,
			)
			return false
		} else {
			return true
		}
	} else if code == 0 {
		t.Fatal("error message implies that expected return code is non-zero")
	} else {
		if gotErr == nil {
			assert.Fail(
				t,
				"codedError validation failure",
				"want error with code %d containing message %q; got no error",
				code,
				wantMsg,
			)
			return false
		}
	}

	coded := &autherr.CodedError{}
	if !errors.As(gotErr, &coded) {
		assert.Fail(t, "failed to unwrap to CodedError", "error of type %T does not wrap a %T. Full error: %v", gotErr, coded, gotErr)
		return false
	}
	if !assert.Equal(t, code, coded.Code) {
		return false
	}
	if !assert.Contains(t, coded.Err.Error(), wantMsg) {
		return false
	}
	return true
}

type fakeAuth struct {
	codeRes       *oauth2.DeviceAuthResponse
	token         *oauth2.Token
	fetchCodeErr  error
	fetchTokenErr error
}

func (f *fakeAuth) FetchCode(ctx context.Context, authEndpint *oauth2.Endpoint) (*oauth2.DeviceAuthResponse, error) {
	return f.codeRes, f.fetchCodeErr
}

func (f *fakeAuth) FetchToken(ctx context.Context, authRes *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	return f.token, f.fetchTokenErr
}

type fakeBrowser struct {
	openErr error
}

func (f *fakeBrowser) Open(u *url.URL) error {
	return f.openErr
}

func encodeFakeAccessToken(subject string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject,
	})
	key := make([]byte, 32)
	s, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}
	return s
}

func TestRun(t *testing.T) {
	expiresInFuture := time.Now().AddDate(0, 0, 7).UTC()
	expiryFormat := "2006-01-02T15:04:05Z"

	testCases := []struct {
		desc string
		args []string

		machineInput  io.Reader
		authenticator oauthdevice.Authenticator
		keyringStore  oauthtoken.LoadStorer
		fileStore     oauthtoken.LoadStorer
		browserOpener browser.Opener
		config        config

		wantCode             int
		wantErr              string
		wantStdoutContaining []string
		wantStderrContaining []string
		wantKeyringStored    []string
		wantFileStored       []string
		wantWriteConfig      bool
	}{
		{
			desc:     "no subcommand",
			args:     nil,
			wantCode: autherr.CodeUnknownSubcommand,
			wantErr:  "expected at least one subcommand",
		},
		{
			desc:     "get with extra args",
			args:     []string{"get", "foo", "bar"},
			wantCode: autherr.CodeBadParams,
			wantErr:  "got 2 args",
		},
		{
			desc:         "get with malformed JSON",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": `),
			wantCode:     autherr.CodeBadParams,
			wantErr:      "failed to parse GetCredentialsRequest",
		},
		{
			desc:         "get with malformed URL",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "//example:malformed/url"}`),
			wantCode:     autherr.CodeBadParams,
			wantErr:      "failed to parse cluster URL",
		},
		{
			desc:         "get propagates token store error",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			keyringStore: &oauthtoken.FakeTokenStore{
				LoadErr: errors.New("token_load_error"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
		},
		{
			desc:         "get with missing token",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			keyringStore: &oauthtoken.FakeTokenStore{
				LoadErr: fmt.Errorf("no such token: %w", fs.ErrNotExist),
			},
			wantCode: autherr.CodeReauthRequired,
			wantErr:  "Please refresh credentials",
		},
		{
			desc:         "get with URL expired",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "access_token",
						Expiry:      time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC),
					},
				},
			},
			wantCode: autherr.CodeReauthRequired,
			wantErr:  "Please refresh credentials",
		},
		{
			desc:         "get with URL not expired",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "access_token",
						Expiry:      expiresInFuture,
					},
				},
			},
			wantStdoutContaining: []string{
				`{"headers":{"x-engflow-auth-method":["jwt-v0"],` +
					`"x-engflow-auth-token":["access_token"]},"expires":` + "\"" + expiresInFuture.Format(expiryFormat) + "\"",
			},
		},
		{
			desc:         "get with file",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			config: config{
				Tokens: []tokenConfig{{
					Cluster: "cluster.example.com",
					Store:   "file",
				}},
			},
			fileStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "access_token",
						Expiry:      expiresInFuture,
					},
				},
			},
			wantStdoutContaining: []string{
				`{"headers":{"x-engflow-auth-method":["jwt-v0"],` +
					`"x-engflow-auth-token":["access_token"]},"expires":` + "\"" + expiresInFuture.Format(expiryFormat) + "\"",
			},
		},
		{
			desc: "version prints build metadata",
			args: []string{"version"},
			// The output of `version` depends on whether stamping is enabled,
			// and is therefore not tested here.
		},
		{
			desc: "help returns no error",
			args: []string{"help"},
			wantStdoutContaining: []string{
				"get",
				"version",
				"help",
				"login",
			},
		},
		{
			desc:     "login without cluster",
			args:     []string{"login"},
			wantCode: autherr.CodeBadParams,
			wantErr:  "expected exactly 1 positional argument",
		},
		{
			desc: "login happy path",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			wantWriteConfig: true,
		},
		{
			desc: "login with alias",
			args: []string{"login", "--alias", "cluster.local.example.com", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			keyringStore: oauthtoken.NewFakeTokenStore(),
			wantKeyringStored: []string{
				"cluster.example.com",
				"cluster.local.example.com",
			},
			wantWriteConfig: true,
		},
		{
			desc: "login with alias with store errors",
			args: []string{"login", "--alias", "cluster.local.example.com", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			keyringStore: &oauthtoken.FakeTokenStore{
				StoreErr: errors.New("token_store_fail"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "2 token store operation(s) failed",
		},
		{
			desc: "login with host and port",
			args: []string{"login", "cluster.example.com:8080"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com:8080/with/auth/code",
				},
			},
			wantWriteConfig: true,
		},
		{
			desc:     "login with invalid scheme",
			args:     []string{"login", "grpcs://cluster.example.com:8080"},
			wantCode: autherr.CodeBadParams,
			wantErr:  "illegal scheme",
		},
		{
			desc: "login code fetch failure",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
				fetchCodeErr: errors.New("fetch_code_fail"),
			},
			wantCode: autherr.CodeAuthFailure,
			wantErr:  "fetch_code_fail",
		},
		{
			desc: "login code fetch RetrieveError",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
				fetchCodeErr: &oauth2.RetrieveError{},
			},
			wantCode: autherr.CodeAuthFailure,
			wantErr:  "This cluster may not support 'engflow_auth login'.\nVisit https://cluster.example.com/gettingstarted for help.",
		},
		{
			desc: "login code fetch unexpected HTML",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
				fetchCodeErr: autherr.UnexpectedHTML,
			},
			wantCode: autherr.CodeAuthFailure,
			wantErr:  "This cluster may not support 'engflow_auth login'.\nVisit https://cluster.example.com/gettingstarted for help.",
		},
		{
			desc: "login browser open failure",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			browserOpener: &fakeBrowser{
				openErr: errors.New("browser_open_fail"),
			},
			wantCode: autherr.CodeAuthFailure,
			wantErr:  "browser_open_fail",
		},
		{
			desc: "login token fetch failure",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
				fetchTokenErr: errors.New("fetch_token_fail"),
			},
			wantCode: autherr.CodeAuthFailure,
			wantErr:  "fetch_token_fail",
		},
		{
			desc: "login token store failure",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			keyringStore: &oauthtoken.FakeTokenStore{
				StoreErr: errors.New("token_store_fail"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "token_store_fail",
		},
		{
			desc: "login subject changed",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
				token: &oauth2.Token{
					AccessToken: encodeFakeAccessToken("alice@example.com"),
				},
			},
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: encodeFakeAccessToken("bob@example.com"),
						Expiry:      expiresInFuture,
					},
				},
			},
			wantStderrContaining: []string{
				"Login identity has changed",
				"bazel shutdown",
			},
			wantWriteConfig: true,
		},
		{
			desc: "login store file",
			args: []string{"login", "-store=file", "cluster.example.com"},
			authenticator: &fakeAuth{
				codeRes: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			wantFileStored:  []string{"cluster.example.com"},
			wantWriteConfig: true,
		},
		{
			desc:     "logout without cluster",
			args:     []string{"logout"},
			wantCode: autherr.CodeBadParams,
			wantErr:  "expected exactly 1 positional argument",
		},
		{
			desc: "logout with unknown cluster",
			args: []string{"logout", "unknown.example.com"},
		},
		{
			desc: "logout with cluster",
			args: []string{"logout", "cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {},
				},
			},
		},
		{
			desc: "logout with error",
			args: []string{"logout", "cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				DeleteErr: errors.New("token_delete_error"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "token_delete_error",
		},
		{
			desc: "logout with file",
			args: []string{"logout", "cluster.example.com"},
			config: config{
				Tokens: []tokenConfig{{
					Cluster: "cluster.example.com",
					Store:   "file",
				}},
			},
			keyringStore: &oauthtoken.FakeTokenStore{
				DeleteErr: errors.New("do_not_call"),
			},
			fileStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {},
				},
			},
			wantWriteConfig: true,
		},
		{
			desc:     "export with no args",
			args:     []string{"export"},
			wantCode: autherr.CodeBadParams,
			wantErr:  "expected exactly 1 positional argument",
		},
		{
			desc:     "export with invalid cluster URL",
			args:     []string{"export", "grpcs://cluster.example.com:8080"},
			wantCode: autherr.CodeBadParams,
			wantErr:  "illegal scheme",
		},
		{
			desc: "export when token not found",
			args: []string{"export", "https://cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				LoadErr: autherr.ReauthRequired("https://cluster.example.com"),
			},
			wantCode: autherr.CodeReauthRequired,
			wantErr:  "expired credentials for cluster",
		},
		{
			desc: "export when token store fails",
			args: []string{"export", "https://cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				LoadErr: fmt.Errorf("token_load_error"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "token_load_error",
		},
		{
			desc: "export when token expired",
			args: []string{"export", "https://cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "access_token",
						Expiry:      time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC),
					},
				},
			},
			wantCode: autherr.CodeReauthRequired,
			wantErr:  "Please refresh credentials",
		},
		{
			desc: "export token",
			args: []string{"export", "https://cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "token_data",
						Expiry:      expiresInFuture,
					},
				},
			},
			wantStdoutContaining: []string{
				`{"token":{"access_token":"token_data",`, // Should have top-level token element
				`,"expiry":"`,                            // Should have token expiry
				`,"cluster_host":"cluster.example.com"`,  // Should have hostname
			},
		},
		{
			desc: "export token with alias",
			args: []string{"export", "--alias", "cluster.local.example.com:8080", "https://cluster.example.com"},
			keyringStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "token_data",
						Expiry:      expiresInFuture,
					},
				},
			},
			wantStdoutContaining: []string{
				`{"token":{"access_token":"token_data",`,        // Should have top-level token element
				`,"expiry":"`,                                   // Should have token expiry
				`,"cluster_host":"cluster.example.com"`,         // Should have hostname
				`,"aliases":["cluster.local.example.com:8080"]`, // Should have aliases
			},
		},
		{
			desc: "export file",
			args: []string{"export", "cluster.example.com"},
			config: config{
				Tokens: []tokenConfig{{
					Cluster: "cluster.example.com",
					Store:   "file",
				}},
			},
			fileStore: &oauthtoken.FakeTokenStore{
				Tokens: map[string]*oauth2.Token{
					"cluster.example.com": {
						AccessToken: "token_data",
						Expiry:      expiresInFuture,
					},
				},
			},
			wantStdoutContaining: []string{
				`{"token":{"access_token":"token_data",`, // Should have top-level token element
				`,"expiry":"`,                            // Should have token expiry
				`,"cluster_host":"cluster.example.com"`,  // Should have hostname
			},
		},
		{
			desc:         "import with no data",
			args:         []string{"import"},
			machineInput: strings.NewReader(""),
			wantCode:     autherr.CodeBadParams,
			wantErr:      "failed to unmarshal token data from stdin",
		},
		{
			desc:         "import with valid data",
			args:         []string{"import"},
			machineInput: strings.NewReader(`{"token":{"access_token":"token_data"},"cluster_host":"cluster.example.com"}`),
			keyringStore: oauthtoken.NewFakeTokenStore(),
			wantKeyringStored: []string{
				"cluster.example.com",
			},
			wantWriteConfig: true,
		},
		{
			desc:         "import with alias",
			args:         []string{"import"},
			machineInput: strings.NewReader(`{"token":{"access_token":"token_data"},"cluster_host":"cluster.example.com","aliases":["cluster.local.example.com"]}`),
			keyringStore: oauthtoken.NewFakeTokenStore(),
			wantKeyringStored: []string{
				"cluster.example.com",
				"cluster.local.example.com",
			},
			wantWriteConfig: true,
		},
		{
			desc:         "import with store error",
			args:         []string{"import"},
			machineInput: strings.NewReader(`{"token":{"access_token":"token_data"},"cluster_host":"cluster.example.com"}`),
			keyringStore: &oauthtoken.FakeTokenStore{
				StoreErr: errors.New("token_store_fail"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "token_store_fail",
		},
		{
			desc:         "import with invalid cluster",
			args:         []string{"import"},
			machineInput: strings.NewReader(`{"token":{"access_token":"token_data"},"cluster_host":"grpcs://cluster.example.com:8080"}`),
			wantCode:     autherr.CodeBadParams,
			wantErr:      "token data contains invalid cluster",
		},
		{
			desc:            "import to file",
			args:            []string{"import", "-store=file"},
			machineInput:    strings.NewReader(`{"token":{"access_token":"token_data"},"cluster_host":"cluster.example.com"}`),
			wantFileStored:  []string{"cluster.example.com"},
			wantWriteConfig: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			stdout := bytes.NewBuffer(nil)
			stderr := bytes.NewBuffer(nil)

			root := &appState{
				browserOpener: tc.browserOpener,
				authenticator: tc.authenticator,
				keyringStore:  tc.keyringStore,
				fileStore:     tc.fileStore,
				config:        tc.config,
			}
			if root.browserOpener == nil {
				root.browserOpener = &fakeBrowser{}
			}
			if root.authenticator == nil {
				root.authenticator = &fakeAuth{}
			}
			if root.keyringStore == nil {
				root.keyringStore = oauthtoken.NewFakeTokenStore()
			}
			if root.fileStore == nil {
				root.fileStore = oauthtoken.NewFakeTokenStore()
			}

			app := makeApp(root)

			// Fake out stdin/stdout/stderr
			app.Reader = tc.machineInput
			if app.Reader == nil {
				app.Reader = strings.NewReader("")
			}
			app.Writer = stdout
			app.ErrWriter = stderr

			// Run the app with a bogus argv[0] that shouldn't affect behavior,
			// but allows CLI parsing to happen as expected.
			gotErr := app.RunContext(ctx, append([]string{"engflow_auth_test"}, tc.args...))

			codedErrorContains(t, gotErr, tc.wantCode, tc.wantErr)

			for _, wantOutput := range tc.wantStdoutContaining {
				if !assert.Contains(
					t,
					stdout.String(),
					wantOutput,
					"stdout doesn't contain expected output",
				) {
					t.Logf("\n====== BEGIN APP STDOUT ======\n%s\n====== END APP STDOUT ======\n\n", stdout.String())
				}
			}
			for _, wantOutput := range tc.wantStderrContaining {
				if !assert.Contains(
					t,
					stderr.String(),
					wantOutput,
					"stderr doesn't contain expected output",
				) {
					t.Logf("\n====== BEGIN APP STDERR ======\n%s\n====== END APP STDERR ======\n\n", stderr.String())
				}
			}
			if tokenStore, ok := tc.keyringStore.(*oauthtoken.FakeTokenStore); ok {
				assert.Subset(t, tokenStore.Tokens, tc.wantKeyringStored)
			}
			if tokenStore, ok := tc.fileStore.(*oauthtoken.FakeTokenStore); ok {
				assert.Subset(t, tokenStore.Tokens, tc.wantFileStored)
			}
			assert.Equal(t, tc.wantWriteConfig, root.writeConfig)
		})
	}
}
