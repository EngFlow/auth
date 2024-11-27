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
	"errors"
	"fmt"
	"io/fs"

	"github.com/EngFlow/auth/internal/oauthtoken"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// loadToken loads a token for the given cluster or returns an error equivalent
// to fs.ErrNotExist if the token is not found in any store.
//
// loadToken may contain logic specific to this app and should be called
// by commands instead of calling LoadStorer.Load directly.
func (r *appState) loadToken(cluster string) (*oauth2.Token, error) {
	var errs []error
	backends := []oauthtoken.LoadStorer{r.keyringStore, r.fileStore}
	for _, backend := range backends {
		token, err := backend.Load(cluster)
		if err == nil {
			return token, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("failed to load token from %d backend(s): %w", len(backends), errors.Join(errs...))
}

// storeToken stores a token for the given cluster in one of the backends.
//
// storeToken may contain logic specific to this app and should be called
// by commands instead of calling LoadStorer.Store directly. For example,
// storeToken prints a message if the token's subject has changed.
func (r *appState) storeToken(cluster string, token *oauth2.Token) error {
	oldToken, err := r.loadToken(cluster)
	if err == nil {
		r.warnIfSubjectChanged(cluster, oldToken, token)
	}

	if r.writeFileStore {
		return r.fileStore.Store(cluster, token)
	} else {
		return r.keyringStore.Store(cluster, token)
	}
}

// warnIfSubjectChanged prints a warning on stderr if the new token belongs to
// a different user than the previously stored token. The user is reminded to
// shutdown Bazel since it caches tokens in memory to avoid running actions
// with the old credential, which is probably still valid.
func (r *appState) warnIfSubjectChanged(cluster string, oldToken, newToken *oauth2.Token) {
	// Disable claims validation, since expired tokens should be allowed to
	// parse.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	oldClaims, newClaims := &jwt.RegisteredClaims{}, &jwt.RegisteredClaims{}
	// Unverified parsing, since issuing a warning vs. not is not a security
	// concern.
	if _, _, err := parser.ParseUnverified(oldToken.AccessToken, oldClaims); err != nil {
		return
	}
	if _, _, err := parser.ParseUnverified(newToken.AccessToken, newClaims); err != nil {
		return
	}
	if oldClaims.Subject != newClaims.Subject {
		fmt.Fprintf(r.stderr, "WARNING: Login identity has changed since last login to %q.\nPlease run `bazel shutdown` in current workspaces in order to ensure bazel picks up new credentials.\n", cluster)
	}
}

// deleteToken removes a token from all of the backends.
//
// deleteToken may contain logic specific to this app and should be called
// by commands instead of calling LoadStorer.Delete directly.
func (r *appState) deleteToken(cluster string) error {
	var errs []error
	// Don't bother to delete from storeBackend, which should also be present in
	// loadBackends
	backends := []oauthtoken.LoadStorer{r.keyringStore, r.fileStore}
	for _, backend := range backends {
		errs = append(errs, backend.Delete(cluster))
	}

	var nonNotFoundErrs []error
	for _, err := range errs {
		if err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			nonNotFoundErrs = append(nonNotFoundErrs, err)
		}
	}
	if err := errors.Join(nonNotFoundErrs...); err != nil {
		return fmt.Errorf("failed to delete token from %d backend(s): %w", len(backends), err)
	}
	return &multiBackendNotFoundError{backendsCount: len(backends)}
}

type multiBackendNotFoundError struct {
	backendsCount int
}

func (m *multiBackendNotFoundError) Error() string {
	return fmt.Sprintf("token for cluster not found after trying %d token storage backends", m.backendsCount)
}

func (m *multiBackendNotFoundError) Is(err error) bool {
	return err == fs.ErrNotExist
}
