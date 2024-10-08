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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os/user"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// KeyringMockInit initializes this package so that its methods may be called
// from a test without reading or writing external state.
func KeyringMockInit() {
	mockUsername = "test"
	keyring.MockInit()
}

var mockUsername string = ""

type keyringNotFoundError struct {
	service string
	user    string
}

func (e *keyringNotFoundError) Error() string {
	return fmt.Sprintf("secret %q for user %q not found in keyring", e.service, e.user)
}

func (e *keyringNotFoundError) Is(err error) bool {
	return err == fs.ErrNotExist
}

// Keyring stores a JWT token on the user's keyring via the OS-specific
// keyring mechanism of the current platform.
type Keyring struct {
	username string
}

var _ LoadStorer = (*Keyring)(nil)

func NewKeyring() (LoadStorer, error) {
	username := mockUsername
	if username == "" {
		u, err := user.Current()
		if err != nil {
			return nil, err
		}
		username = u.Username
	}
	return &Keyring{
		username: username,
	}, nil
}

func (f *Keyring) Load(cluster string) (*oauth2.Token, error) {
	serviceName := f.secretServiceName(cluster)
	contents, err := keyring.Get(serviceName, f.username)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, &keyringNotFoundError{service: serviceName, user: f.username}
		}
		return nil, fmt.Errorf("failed to look up token for service %q: %w", serviceName, err)
	}

	parsed := &oauth2.Token{}
	if err := json.Unmarshal([]byte(contents), parsed); err != nil {
		return nil, fmt.Errorf("failed to parse oauth2 token from keyring service %q: %w", serviceName, err)
	}
	return parsed, nil
}

func (f *Keyring) Store(cluster string, token *oauth2.Token) error {
	serviceName := f.secretServiceName(cluster)
	tokenStr, err := json.Marshal(token)
	if err != nil {
		return err
	}

	err = keyring.Set(serviceName, f.username, string(tokenStr))
	if err != nil {
		return fmt.Errorf("failed to store token in OS keyring service %q: %w", serviceName, err)
	}

	return nil
}

func (f *Keyring) Delete(cluster string) error {
	serviceName := f.secretServiceName(cluster)
	if err := keyring.Delete(serviceName, f.username); errors.Is(err, keyring.ErrNotFound) {
		return &keyringNotFoundError{user: f.username, service: serviceName}
	} else if err != nil {
		return fmt.Errorf("failed to delete oauth2 token from keyring service %q: %w", serviceName, err)
	}
	return nil
}

func (f *Keyring) secretServiceName(cluster string) string {
	return fmt.Sprintf("engflow.com/engflow_auth/%s", cluster)
}
