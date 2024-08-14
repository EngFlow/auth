package oauthdevice

import (
	"context"

	"github.com/EngFlow/auth/internal/autherr"
	"golang.org/x/oauth2"
)

type VersionCase struct {
	matchFn func(version string) bool
	impl    Authenticator
}

func NewVersionCase(impl Authenticator, matchFn func(version string) bool) *VersionCase {
	return &VersionCase{
		matchFn: matchFn,
		impl:    impl,
	}
}

type ServerVersioning struct {
	matchers    []*VersionCase
	defaultImpl Authenticator
}

func NewServerVersioning(matchers []*VersionCase, defaultImpl Authenticator) (*ServerVersioning, error) {
	return &ServerVersioning{
		matchers:    matchers,
		defaultImpl: defaultImpl,
	}, nil
}

func (v *ServerVersioning) FetchCode(ctx context.Context, authEndpoint *oauth2.Endpoint) (*oauth2.DeviceAuthResponse, error) {
	serverVersion, err := v.getServerVersion(ctx)
	if err != nil {
		return nil, autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to query server version: %w", err)
	}
	return v.selectBackend(serverVersion).FetchCode(ctx, authEndpoint)
}

func (v *ServerVersioning) FetchToken(ctx context.Context, authRes *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	serverVersion, err := v.getServerVersion(ctx)
	if err != nil {
		return nil, autherr.CodedErrorf(autherr.CodeAuthFailure, "failed to query server version: %w", err)
	}
	return v.selectBackend(serverVersion).FetchToken(ctx, authRes)
}

func (v *ServerVersioning) getServerVersion(ctx context.Context) (string, error) {
	return "", autherr.CodedErrorf(autherr.CodeUnimplemented, "getServerVersion() not implemented")
}

func (v *ServerVersioning) selectBackend(serverVersion string) Authenticator {
	for _, matcher := range v.matchers {
		if matcher.matchFn(serverVersion) {
			return matcher.impl
		}
	}
	return v.defaultImpl
}
