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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/EngFlow/auth/internal/autherr"
	"github.com/EngFlow/auth/internal/browser"
	"github.com/EngFlow/auth/internal/buildstamp"
	"github.com/EngFlow/auth/internal/oauthdevice"
	"github.com/EngFlow/auth/internal/oauthtoken"
	"github.com/urfave/cli/v2"

	credentialhelper "github.com/EngFlow/credential-helper-go"
	"golang.org/x/oauth2"
)

const (
	// Arbitrarily-chosen string of random hex data. This must match the
	// backend's expectation of the client ID.
	cliClientID = "69a59a782cbce2a1bda9d6e643a20e0c08f630fbf0d960674376a70f0b1942a9"
)

type appState struct {
	browserOpener browser.Opener
	authenticator oauthdevice.Authenticator
	tokenStore    oauthtoken.LoadStorer
}

type ExportedToken struct {
	// OAuth2 token as returned from EngFlow auth endpoints
	Token *oauth2.Token `json:"token"`
	// Hostname of the cluster token was issued from
	ClusterHost string `json:"cluster_host"`
	// List of alternative hostnames for this cluster, for which this token
	// should also apply
	Aliases []string `json:"aliases,omitempty"`
}

func (r *appState) get(cliCtx *cli.Context) error {
	ctx := cliCtx.Context

	if cliCtx.NArg() != 0 {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected no positional args; got %d args: %v", cliCtx.NArg(), cliCtx.Args())
	}
	var req credentialhelper.GetCredentialsRequest
	if err := json.NewDecoder(cliCtx.App.Reader).Decode(&req); err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "failed to parse GetCredentialsRequest: %w", err)
	}
	clusterURL, err := url.Parse(req.URI)
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "failed to parse cluster URL %q from request: %w", req.URI, err)
	}
	token, err := r.tokenStore.Load(ctx, clusterURL.Host)
	if err != nil {
		return autherr.ReauthRequired(clusterURL.Host)
	}
	if time.Now().After(token.Expiry) {
		return autherr.ReauthRequired(clusterURL.Host)
	}
	res := &credentialhelper.GetCredentialsResponse{
		Headers: map[string][]string{
			"x-engflow-auth-token":  {token.AccessToken},
			"x-engflow-auth-method": {"jwt-v0"},
		},
		Expires: &token.Expiry,
	}
	if err := json.NewEncoder(cliCtx.App.Writer).Encode(res); err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected exactly 1 positional argument, a cluster host name; got %d", cliCtx.NArg())
	}
	return nil
}

func (r *appState) export(cliCtx *cli.Context) error {
	ctx := cliCtx.Context

	if cliCtx.NArg() != 1 {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected exactly 1 positional argument, a cluster host name; got %d arguments", cliCtx.NArg())
	}
	clusterURL, err := sanitizedURL(cliCtx.Args().Get(0))
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "invalid cluster: %w", err)
	}

	token, err := r.tokenStore.Load(ctx, clusterURL.Host)
	if err != nil {
		if reauthErr := (*autherr.CodedError)(nil); errors.As(err, &reauthErr) && reauthErr.Code == autherr.CodeReauthRequired {
			return reauthErr
		}
		return autherr.CodedErrorf(autherr.CodeTokenStoreFailure, "failed to fetch token for cluster %q: %w", clusterURL.Host, err)
	}

	if time.Now().After(token.Expiry) {
		return autherr.ReauthRequired(clusterURL.Host)
	}

	export := &ExportedToken{
		Token:       token,
		ClusterHost: clusterURL.Host,
		Aliases:     cliCtx.StringSlice("alias"),
	}

	if err := json.NewEncoder(cliCtx.App.Writer).Encode(export); err != nil {
		return autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to marshal token info: %w", err)
	}
	return nil
}

func (r *appState) login(cliCtx *cli.Context) error {
	ctx := cliCtx.Context

	if cliCtx.NArg() != 1 {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected exactly 1 positional argument, a cluster name")
	}
	clusterURL, err := sanitizedURL(cliCtx.Args().Get(0))
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "invalid cluster: %w", err)
	}
	oauthURL := oauthEndpoint(clusterURL)

	// Tokens fetched during the process will be associated with each URL in
	// storeURLs in the token store
	storeURLs := []*url.URL{clusterURL}
	for _, alias := range cliCtx.StringSlice("alias") {
		if aliasURL, err := sanitizedURL(alias); err != nil {
			return autherr.CodedErrorf(autherr.CodeBadParams, "invalid alias host: %w", err)
		} else {
			storeURLs = append(storeURLs, aliasURL)
		}
	}

	authRes, err := r.authenticator.FetchCode(ctx, oauthURL)
	if err != nil {
		if oauthErr := (*oauth2.RetrieveError)(nil); errors.Is(err, autherr.UnexpectedHTML) || errors.As(err, &oauthErr) {
			return autherr.CodedErrorf(
				autherr.CodeAuthFailure,
				`from OAuth2 endpoint %s: %w
This cluster may not support 'engflow_auth login'.
Visit %s for help.`,
				oauthURL.DeviceAuthURL,
				err,
				clusterURL.String()+"/gettingstarted",
			)
		}
		return autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to generate device code: %w", err)
	}
	// The "complete" URI that includes the device code pre-populated is ideal,
	// but technically optional. Prefer it, but fall back to the required URL in
	// the response if necessary.
	verificationURLStr := authRes.VerificationURIComplete
	if verificationURLStr == "" {
		verificationURLStr = authRes.VerificationURI
	}
	verificationURL, err := url.Parse(verificationURLStr)
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to parse authentication URL: %w", err)
	}
	if err := r.browserOpener.Open(verificationURL); err != nil {
		return autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to open browser to perform authentication: %w", err)
	}
	token, err := r.authenticator.FetchToken(ctx, authRes)
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to obtain auth token: %w", err)
	}

	var storeErrs []error
	for _, storeURL := range storeURLs {
		if err := r.tokenStore.Store(ctx, storeURL.Host, token); err != nil {
			storeErrs = append(storeErrs, fmt.Errorf("failed to save token for host %q: %w", storeURL.Host, err))
		}
	}
	if err := errors.Join(storeErrs...); err != nil {
		return autherr.CodedErrorf(
			autherr.CodeTokenStoreFailure,
			"%d token store operation(s) failed:\n%v",
			len(storeErrs),
			err,
		)
	}

	fmt.Fprintf(
		cliCtx.App.ErrWriter,
		"Successfully saved credentials for %[1]s.\nTo use, ensure the line below is in your .bazelrc:\n\n\tbuild --credential_helper=%[1]s=%s\n",
		clusterURL.Hostname(),
		os.Args[0])

	return nil
}

func (r *appState) logout(cliCtx *cli.Context) error {
	if cliCtx.NArg() != 1 {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected exactly 1 positional argument, a cluster name")
	}
	clusterURL, err := sanitizedURL(cliCtx.Args().Get(0))
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "invalid cluster: %w", err)
	}

	if err := r.tokenStore.Delete(cliCtx.Context, clusterURL.Host); err != nil {
		return &autherr.CodedError{Code: autherr.CodeTokenStoreFailure, Err: err}
	}
	return nil
}

func (r *appState) version(cliCtx *cli.Context) error {
	fmt.Fprintf(cliCtx.App.Writer, "%s\n", buildstamp.Values)
	return nil
}

func makeApp(root *appState) *cli.App {
	app := &cli.App{
		Name:  "engflow_auth",
		Usage: "Authenticate to EngFlow remote build clusters",
		Commands: []*cli.Command{
			{
				Name:  "get",
				Usage: "Act as a bazel credential helper to provide credentials for a particular cluster",
				UsageText: strings.TrimSpace(`
Reads a Bazel credential helper request JSON payload from stdin and
responds with a Bazel credential helper response JSON payload over
stdout.

This command should only be used by tools that understand the Bazel
credential helper protocol.`),
				Action: root.get,
			},
			{
				Name:      "export",
				Usage:     "Prints the currently-stored token for the specified cluster to stdout",
				ArgsUsage: " CLUSTER_URL",
				Action:    root.export,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "alias",
						Usage: "Comma-separated list of alias hostnames for this cluster",
					},
				},
			},
			{
				Name:      "login",
				Usage:     "Generate and store credentials for a particular cluster",
				ArgsUsage: " CLUSTER_URL",
				UsageText: strings.TrimSpace(`
Initiates an interactive OAuth2 flow to log into the cluster at
CLUSTER_URL.`),
				Action: root.login,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "alias",
						Usage: "Comma-separated list of alias hostnames for this cluster",
					},
				},
			},
			{
				Name:      "logout",
				Usage:     "Remove a cluster's credentials from this machine",
				ArgsUsage: " CLUSTER_URL",
				UsageText: strings.TrimSpace(`
Erases the credentials for the named cluster from the local machine.`),
				Action: root.logout,
			},
			{
				Name:   "version",
				Usage:  "Print version info for this application",
				Action: root.version,
			},
		},
		Before: func(ctx *cli.Context) error {
			// Exit non-zero if no subcommand is provided (CLI library will take
			// care of printing the help message, if applicable)
			if ctx.NArg() < 1 {
				return autherr.CodedErrorf(autherr.CodeUnknownSubcommand, "no subcommand provided; expected at least one subcommand")
			}
			return nil
		},
		ExitErrHandler: func(cCtx *cli.Context, err error) {
			// The default handler will call os.Exit(); we want to do nothing so
			// that the error is returned to the caller of app.RunContext(), and
			// we will take care of calling os.Exit().
		},
	}
	return app
}

func main() {
	// Catch Ctrl-C and propagate it to any I/O that is context-aware
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	deviceAuth := oauthdevice.NewAuth(cliClientID, nil)
	browserOpener := &browser.StderrPrint{}
	tokenStore, err := oauthtoken.NewKeyring()
	if err != nil {
		exitOnError(autherr.CodedErrorf(autherr.CodeTokenStoreFailure, "failed to open token store: %w", err))
	}
	root := &appState{
		browserOpener: browserOpener,
		authenticator: deviceAuth,
		tokenStore:    oauthtoken.NewCacheAlert(tokenStore, os.Stderr),
	}

	app := makeApp(root)
	exitOnError(app.RunContext(ctx, os.Args))
}

func exitOnError(err error) {
	if err == nil {
		return
	}
	// If the subcommand failed, show the error and exit non-zero, using the
	// exit code provided by the error if possible.
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)

	if coded := (*autherr.CodedError)(nil); errors.As(err, &coded) {
		os.Exit(coded.Code)
	}

	os.Exit(autherr.CodeUnknownError)
}

func sanitizedURL(cluster string) (*url.URL, error) {
	clusterURL, err := url.Parse(cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster name to URL: %w", err)
	}
	// If the scheme is omitted (e.g. `cluster.example.com`), then it may get
	// parsed as the URL path rather than the host.
	if clusterURL.Host == "" {
		if clusterURL.Path != "" {
			clusterURL.Host, clusterURL.Path = clusterURL.Path, ""
		} else if clusterURL.Opaque != "" {
			// The URL got parsed as `scheme:opaque[?query][#fragment]` - see
			// https://stackoverflow.com/q/62083272. This can happen if the user
			// passes a naked host:port, like cluster.example.com:8080.
			// In this case, the host got parsed as the scheme, and the port got
			// parsed as `opaque`.
			clusterURL.Host = net.JoinHostPort(clusterURL.Scheme, clusterURL.Opaque)
			clusterURL.Scheme, clusterURL.Opaque = "", ""
		} else {
			return nil, fmt.Errorf("failed to identify host of cluster URL %q", cluster)
		}
	}
	if clusterURL.Scheme == "" {
		clusterURL.Scheme = "https"
	}

	// Sanitize user input:
	// - `Host` is required
	// - `Scheme` is optional, defaulting to `https`
	// - `Port` is optional, defaulting to whatever is implied by `Scheme`
	// - All other fields are forbidden
	if clusterURL.Scheme != "https" {
		return nil, fmt.Errorf("illegal scheme %q; only 'https' is supported", clusterURL.Scheme)
	}
	if clusterURL.Host == "" {
		return nil, fmt.Errorf("cluster URL %q does not specify a host", clusterURL)
	}
	if clusterURL.User != nil {
		return nil, fmt.Errorf("cluster URL %q should not specify URL user component", clusterURL)
	}
	if clusterURL.Path != "" {
		return nil, fmt.Errorf("cluster URL %q should not specify URL path component", clusterURL)
	}
	if clusterURL.RawQuery != "" {
		return nil, fmt.Errorf("cluster URL %q should not specify URL query component", clusterURL)
	}
	if clusterURL.Fragment != "" {
		return nil, fmt.Errorf("cluster URL %q should not specify URL fragment", clusterURL)
	}
	return clusterURL, nil
}

func urlWithPath(u *url.URL, path string) *url.URL {
	newURL := &url.URL{}
	*newURL = *u
	newURL.Path = path
	return newURL
}

func oauthEndpoint(u *url.URL) *oauth2.Endpoint {
	return &oauth2.Endpoint{
		DeviceAuthURL: urlWithPath(u, "api/v1/oauth2/device").String(),
		TokenURL:      urlWithPath(u, "api/v1/oauth2/token").String(),
		AuthStyle:     oauth2.AuthStyleInParams,
	}
}
