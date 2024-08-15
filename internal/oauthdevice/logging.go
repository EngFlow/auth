package oauthdevice

import (
	"context"
	"io"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/oauth2"
)

type HTTPLogging struct {
	Impl Authenticator
}

func (l *HTTPLogging) FetchCode(ctx context.Context, endpoint *oauth2.Endpoint) (*oauth2.DeviceAuthResponse, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: &spewingTransport{impl: http.DefaultTransport}})
	return l.Impl.FetchCode(ctx, endpoint)
}

func (l *HTTPLogging) FetchToken(ctx context.Context, authRes *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: &spewingTransport{impl: http.DefaultTransport}})
	return l.Impl.FetchToken(ctx, authRes)
}

type spewingTransport struct {
	impl http.RoundTripper
}

func (s *spewingTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	config := spew.NewDefaultConfig()
	config.Indent = "  "
	config.DisableCapacities = true
	config.DisablePointerAddresses = true
	config.MaxDepth = 2
	config.Dump(req)
	defer func() {
		res.Body = io.NopCloser(io.TeeReader(res.Body, os.Stderr))
		config.Dump(res)
	}()
	return s.impl.RoundTrip(req)
}
