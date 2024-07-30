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

package oauthtoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/user"

	"github.com/EngFlow/auth/internal/autherr"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

var (
	// Shim external functions to stub them while testing
	keyringGet = keyring.Get
	keyringSet = keyring.Set
)

// Keyring stores a JWT token on the user's keyring via the OS-specific
// keyring mechanism of the current platform.
type Keyring struct {
	username string
}

func NewKeyring() (LoadStorer, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	return &Keyring{
		username: u.Username,
	}, nil
}

func (f *Keyring) Load(ctx context.Context, cluster string) (*oauth2.Token, error) {
	serviceName := f.secretServiceName(cluster)
	contents, err := keyringGet(serviceName, f.username)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, autherr.ReauthRequired(cluster)
		}
		return nil, fmt.Errorf("failed to look up token for service %q: %w", serviceName, err)
	}

	parsed := &oauth2.Token{}
	if err := json.Unmarshal([]byte(contents), parsed); err != nil {
		return nil, fmt.Errorf("failed to parse oauth2 token from keyring service %q: %w", serviceName, err)
	}
	return parsed, nil
}

func (f *Keyring) Store(ctx context.Context, cluster string, token *oauth2.Token) error {
	serviceName := f.secretServiceName(cluster)
	tokenStr, err := json.Marshal(token)
	if err != nil {
		return err
	}

	err = keyringSet(serviceName, f.username, string(tokenStr))
	if err != nil {
		return fmt.Errorf("failed to store token in OS keyring service %q: %w", serviceName, err)
	}

	return nil
}

func (f *Keyring) secretServiceName(cluster string) string {
	return fmt.Sprintf("engflow.com/engflow_auth/%s", cluster)
}
