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
	"os"

	"github.com/EngFlow/auth/internal/oauthtoken"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// loadToken loads a token for the given cluster or returns an error equivalent
// to fs.ErrNotExist if the token is not found in any store.
//
// NOTE(REC-110): loadToken attempts to load from the file store first, falling
// back to the keyring if an unencrypted token is not found. On Linux, the
// keyring library may try to prompt the user for a password, hanging forever
// because stdin and stdout are not normally connected to a terminal. We should
// avoid calling it at all if the token is not stored there.
//
// loadToken may contain logic specific to this app and should be called
// by commands instead of calling LoadStorer.Load directly.
func (r *appState) loadToken(cluster string) (*oauth2.Token, error) {
	token, fileErr := r.fileStore.Load(cluster)
	if fileErr == nil {
		return token, nil
	}
	var keyringErr error
	if !r.writeFileStore {
		token, keyringErr = r.keyringStore.Load(cluster)
		if keyringErr == nil {
			return token, nil
		}
	}
	return nil, fmt.Errorf("failed to load token: %w", errors.Join(fileErr, keyringErr))
}

// storeToken stores a token for the given cluster in one of the backends.
//
// NOTE(REC-110): when -store=file is used, storeToken only writes to the file
// store and ignores the keyring store. When -store=file is not used,
// storedToken writes to the keyring store deletes then token from the file
// store if present. On Linux, the keyring library may try to prompt the user
// for a password, causing loadToken to hang forever when invoked later.
// So if -store=file is used, we should avoid calling the keyring library,
// now or in the future.
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
		if err := r.fileStore.Delete(cluster); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: attempting to delete existing file token: %v", err)
		}
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
		return fmt.Errorf("failed to delete token: %w", err)
	}
	return errors.Join(errs...)
}
