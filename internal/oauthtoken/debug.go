package oauthtoken

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

type DebugPrint struct{}

func (d *DebugPrint) Store(ctx context.Context, cluster string, token *oauth2.Token) error {
	fmt.Fprintf(os.Stderr, "Token for cluster %q: %#v\n", cluster, token)
	return nil
}

func (d *DebugPrint) Load(ctx context.Context, cluster string) (*oauth2.Token, error) {
	return nil, errors.New("debug-printing token store is not able to load tokens")
}
