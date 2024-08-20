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
	"errors"
	"io/fs"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

func init() {
	// Use a mock keyring during tests, since the real implementation has global
	// side effects in the user's environment. We could use the real
	// implementation with a fake name, but:
	// - On macOS, Bazel's sandbox blocks access to the keychain.
	// - On Linux, dbus-launcher is not available in the test environment.
	keyring.MockInit()
}

func TestKeyringLoadError(t *testing.T) {
	wantErr := errors.New("load_error")
	keyring.MockInitWithError(wantErr)
	t.Cleanup(keyring.MockInit)
	testKeyring := &Keyring{username: "jmcclane"}
	cluster := "nakatomiplaza.cluster.engflow.com"
	_, gotErr := testKeyring.Load(cluster)
	require.ErrorIs(t, gotErr, wantErr)
	require.ErrorContains(t, gotErr, "failed to look up token")
}

func TestKeyringStoreError(t *testing.T) {
	wantErr := errors.New("store_error")
	keyring.MockInitWithError(wantErr)
	t.Cleanup(keyring.MockInit)
	testKeyring := &Keyring{username: "jmcclane"}
	cluster := "nakatomiplaza.cluster.engflow.com"
	token := &oauth2.Token{
		AccessToken: uuid.New().String(),
	}
	gotErr := testKeyring.Store(cluster, token)
	require.ErrorIs(t, gotErr, wantErr)
	require.ErrorContains(t, gotErr, "failed to store token")
}

func TestKeyringNotFoundError(t *testing.T) {
	err := &keyringNotFoundError{user: "jmcclane", service: "nypd"}
	assert.ErrorIs(t, err, fs.ErrNotExist)
}
