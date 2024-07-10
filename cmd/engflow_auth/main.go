package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

	credentialhelper "github.com/EngFlow/credential-helper-go"
	"golang.org/x/oauth2"
)

const (
	// Arbitrarily-chosen string of random hex data. This must match the
	// backend's expectation of the client ID.
	cliClientID = "69a59a782cbce2a1bda9d6e643a20e0c08f630fbf0d960674376a70f0b1942a9"
)

func showHelp(stream io.Writer) {
	fmt.Fprintf(stream, `engflow_auth: Manage authentication to engflow clusters

Commands:

	get
		Reads a Bazel credential helper request JSON payload from stdin and
		responds with a Bazel credential helper response JSON payload over
		stdout.

		This command should only be used by tools that understand the Bazel
		credential helper protocol.

	help
		Shows this info.

	login <CLUSTER_URL>
		Initiates an interactive OAuth flow to log into the cluster at
		CLUSTER_URL.

		Example:

			engflow_auth login example.cluster.engflow.com

	version
		Prints version information.
`)
}

type rootCmd struct {
	browserOpener browser.Opener
	authenticator oauthdevice.Authenticator
	tokenStore    oauthtoken.LoadStorer
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
}

func (r *rootCmd) get(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected no positional args; got %d args: %v", len(args), args)
	}
	var req credentialhelper.GetCredentialsRequest
	if err := json.NewDecoder(r.stdin).Decode(&req); err != nil {
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
	if err := json.NewEncoder(r.stdout).Encode(res); err != nil {
		return autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to marshal GetCredentialsResponse to JSON: %w", err)
	}
	return nil
}

func (r *rootCmd) login(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	aliasFlag := flags.String("alias", "", "Comma-separated list of alias hostnames for this cluster")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			showHelp(r.stderr)
			return nil
		}
		return autherr.CodedErrorf(autherr.CodeBadParams, "failed to process flags for `login`: %w", err)
	}

	if flags.NArg() != 1 {
		return autherr.CodedErrorf(autherr.CodeBadParams, "expected exactly 1 positional argument, a cluster name")
	}
	clusterURL, err := sanitizedURL(flags.Arg(0))
	if err != nil {
		return autherr.CodedErrorf(autherr.CodeBadParams, "invalid cluster: %w", err)
	}
	oauthURL := oauthEndpoint(clusterURL)

	// Tokens fetched during the process will be associated with each URL in
	// storeURLs in the token store
	storeURLs := []*url.URL{clusterURL}
	if *aliasFlag != "" {
		for _, alias := range strings.Split(*aliasFlag, ",") {
			if aliasURL, err := sanitizedURL(alias); err != nil {
				return autherr.CodedErrorf(autherr.CodeBadParams, "invalid alias host: %w", err)
			} else {
				storeURLs = append(storeURLs, aliasURL)
			}
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
		r.stderr,
		"Successfully saved credentials for %[1]s.\nTo use, ensure the line below is in your .bazelrc:\n\n\tbuild --credential_helper=%[1]s=%s\n",
		clusterURL.Hostname(),
		os.Args[0])

	return nil
}

func (r *rootCmd) version(ctx context.Context, args []string) error {
	fmt.Fprintf(r.stdout, "%s", buildstamp.Values)
	return nil
}

func (r *rootCmd) help(ctx context.Context, args []string) error {
	showHelp(r.stderr)
	return nil
}

func (r *rootCmd) run(ctx context.Context, args []string) error {
	// No subcommand; show help text + clear error and exit
	if len(args) == 0 {
		showHelp(r.stderr)
		return autherr.CodedErrorf(autherr.CodeUnknownSubcommand, "expected at least one subcommand")
	}

	subCmdName, subCmdArgs := args[0], args[1:]
	switch subCmdName {
	case "get":
		return r.get(ctx, subCmdArgs)
	case "version":
		return r.version(ctx, subCmdArgs)
	case "help":
		return r.help(ctx, subCmdArgs)
	case "login":
		return r.login(ctx, subCmdArgs)
	default:
		showHelp(r.stderr)
		return autherr.CodedErrorf(autherr.CodeUnknownSubcommand, "unknown subcommand %q", subCmdName)
	}
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
	root := &rootCmd{
		browserOpener: browserOpener,
		authenticator: deviceAuth,
		tokenStore:    oauthtoken.NewCacheAlert(tokenStore, os.Stderr),
		stdin:         os.Stdin,
		stdout:        os.Stdout,
		stderr:        os.Stderr,
	}
	exitOnError(root.run(ctx, os.Args[1:]))
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
