package oauthtoken

import (
	"context"
	"fmt"
	"io"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// CacheAlert is a tokenLoadStorer that detects when a token's subject for
// a different cluster is changing, and produces a warning over an appropriate
// communication channel.
type CacheAlert struct {
	impl   LoadStorer
	stderr io.Writer
}

func NewCacheAlert(impl LoadStorer, stderr io.Writer) LoadStorer {
	return &CacheAlert{
		impl:   impl,
		stderr: stderr,
	}
}

func (a *CacheAlert) Store(ctx context.Context, cluster string, token *oauth2.Token) error {
	oldToken, err := a.impl.Load(ctx, cluster)
	if err != nil || oldToken == nil {
		// Failed to fetch any sort of previous valid token. Defer to the
		// wrapped implementation; we'll assume that the token didn't exist
		// previously (and therefore no need to issue a warning).
		return a.impl.Store(ctx, cluster, token)
	}

	// Disable claims validation, since expired tokens should be allowed to
	// parse.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	oldClaims, newClaims := &jwt.RegisteredClaims{}, &jwt.RegisteredClaims{}
	// Unverified parsing, since issuing a warning vs. not is not a security
	// concern.
	_, _, err = parser.ParseUnverified(oldToken.AccessToken, oldClaims)
	if err != nil {
		return a.impl.Store(ctx, cluster, token)
	}
	_, _, err = parser.ParseUnverified(token.AccessToken, newClaims)
	if err != nil {
		return a.impl.Store(ctx, cluster, token)
	}

	if oldClaims.Subject != newClaims.Subject {
		fmt.Fprintf(a.stderr, "WARNING: Login identity has changed since last login to %q.\nPlease run `bazel shutdown` in current workspaces in order to ensure bazel picks up new credentials.\n", cluster)
	}

	return a.impl.Store(ctx, cluster, token)
}

func (a *CacheAlert) Load(ctx context.Context, cluster string) (*oauth2.Token, error) {
	return a.impl.Load(ctx, cluster)
}
