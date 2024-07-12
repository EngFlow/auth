package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/EngFlow/auth/internal/autherr"
	"github.com/EngFlow/auth/internal/browser"
	"github.com/EngFlow/auth/internal/oauthdevice"
	"github.com/EngFlow/auth/internal/oauthtoken"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
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

	var coded cli.ExitCoder
	if !errors.As(gotErr, &coded) {
		assert.Fail(t, "failed to unwrap to CodedError", "error of type %T does not wrap a %T", gotErr, coded)
		return false
	}
	if !assert.Equal(t, code, coded.ExitCode()) {
		return false
	}
	if !assert.Contains(t, coded.Error(), wantMsg) {
		return false
	}
	return true
}

type fakeAuth struct {
	res           *oauth2.DeviceAuthResponse
	fetchCodeErr  error
	fetchTokenErr error
}

func (f *fakeAuth) FetchCode(ctx context.Context, authEndpint *oauth2.Endpoint) (*oauth2.DeviceAuthResponse, error) {
	return f.res, f.fetchCodeErr
}

func (f *fakeAuth) FetchToken(ctx context.Context, authRes *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	return nil, f.fetchTokenErr
}

type fakeStore struct {
	loadToken     *oauth2.Token
	loadErr       error
	storeErr      error
	storeClusters []string
}

func (f *fakeStore) Load(ctx context.Context, cluster string) (*oauth2.Token, error) {
	return f.loadToken, f.loadErr
}

func (f *fakeStore) Store(ctx context.Context, cluster string, token *oauth2.Token) error {
	f.storeClusters = append(f.storeClusters, cluster)
	return f.storeErr
}

type fakeBrowser struct {
	openErr error
}

func (f *fakeBrowser) Open(u *url.URL) error {
	return f.openErr
}

func TestRun(t *testing.T) {
	expiresInFuture := time.Now().AddDate(0, 0, 7).UTC()
	expiryFormat := "2006-01-02T15:04:05Z"

	testCases := []struct {
		desc string
		args []string

		machineInput  io.Reader
		authenticator oauthdevice.Authenticator
		tokenStore    oauthtoken.LoadStorer
		browserOpener browser.Opener

		wantCode             int
		wantErr              string
		wantStdoutContaining []string
		wantStderrContaining []string
		wantStoreCallsFor    []string
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
			tokenStore: &fakeStore{
				loadErr: errors.New("token_load_error"),
			},
			wantCode: autherr.CodeReauthRequired,
			wantErr:  "Please refresh credentials",
		},
		{
			desc:         "get with URL expired",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			tokenStore: &fakeStore{
				loadToken: &oauth2.Token{
					AccessToken: "access_token",
					Expiry:      time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC),
				},
			},
			wantCode: autherr.CodeReauthRequired,
			wantErr:  "Please refresh credentials",
		},
		{
			desc:         "get with URL not expired",
			args:         []string{"get"},
			machineInput: strings.NewReader(`{"uri": "https://cluster.example.com"}`),
			tokenStore: &fakeStore{
				loadToken: &oauth2.Token{
					AccessToken: "access_token",
					Expiry:      expiresInFuture,
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
			wantStderrContaining: []string{
				"get",
				"version",
				"help",
				"login <CLUSTER_URL>",
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
				res: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
		},
		{
			desc: "login with alias",
			args: []string{"login", "--alias", "cluster.local.example.com", "cluster.example.com"},
			authenticator: &fakeAuth{
				res: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			tokenStore: &fakeStore{},
			wantStoreCallsFor: []string{
				"cluster.example.com",
				"cluster.local.example.com",
			},
		},
		{
			desc: "login with alias with store errors",
			args: []string{"login", "--alias", "cluster.local.example.com", "cluster.example.com"},
			authenticator: &fakeAuth{
				res: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			tokenStore: &fakeStore{
				storeErr: errors.New("token_store_fail"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "2 token store operation(s) failed",
			wantStoreCallsFor: []string{
				"cluster.example.com",
				"cluster.local.example.com",
			},
		},
		{
			desc: "login with host and port",
			args: []string{"login", "cluster.example.com:8080"},
			authenticator: &fakeAuth{
				res: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com:8080/with/auth/code",
				},
			},
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
				res: &oauth2.DeviceAuthResponse{
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
				res: &oauth2.DeviceAuthResponse{
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
				res: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
				fetchCodeErr: autherr.ErrUnexpectedHTML,
			},
			wantCode: autherr.CodeAuthFailure,
			wantErr:  "This cluster may not support 'engflow_auth login'.\nVisit https://cluster.example.com/gettingstarted for help.",
		},
		{
			desc: "login browser open failure",
			args: []string{"login", "cluster.example.com"},
			authenticator: &fakeAuth{
				res: &oauth2.DeviceAuthResponse{
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
				res: &oauth2.DeviceAuthResponse{
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
				res: &oauth2.DeviceAuthResponse{
					VerificationURIComplete: "https://cluster.example.com/with/auth/code",
				},
			},
			tokenStore: &fakeStore{
				storeErr: errors.New("token_store_fail"),
			},
			wantCode: autherr.CodeTokenStoreFailure,
			wantErr:  "token_store_fail",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			oldExitFunc := cli.OsExiter
			defer func() {
				cli.OsExiter = oldExitFunc
			}()
			cli.OsExiter = func(int) {}

			ctx := context.Background()
			stdout := bytes.NewBuffer(nil)
			stderr := bytes.NewBuffer(nil)

			root := &rootCmd{
				browserOpener: tc.browserOpener,
				authenticator: tc.authenticator,
				tokenStore:    tc.tokenStore,
				stdin:         tc.machineInput,
				stdout:        stdout,
				stderr:        stderr,
			}
			if root.stdin == nil {
				root.stdin = strings.NewReader("")
			}
			if root.browserOpener == nil {
				root.browserOpener = &fakeBrowser{}
			}
			if root.authenticator == nil {
				root.authenticator = &fakeAuth{}
			}
			if root.tokenStore == nil {
				root.tokenStore = &fakeStore{}
			}

			gotErr := root.run(ctx, append([]string{"engflow_auth"}, tc.args...))

			codedErrorContains(t, gotErr, tc.wantCode, tc.wantErr)

			for _, wantOutput := range tc.wantStdoutContaining {
				assert.Contains(
					t,
					stdout.String(),
					wantOutput,
					"stdout doesn't contain expected output",
				)
			}
			for _, wantOutput := range tc.wantStderrContaining {
				assert.Contains(
					t,
					stderr.String(),
					wantOutput,
					"stderr doesn't contain expected output",
				)
			}
			if tokenStore, ok := tc.tokenStore.(*fakeStore); ok {
				assert.Subset(t, tokenStore.storeClusters, tc.wantStoreCallsFor)
			}
		})
	}
}
