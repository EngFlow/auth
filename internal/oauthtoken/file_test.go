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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestTokenRoundtrip(t *testing.T) {
	configDir := t.TempDir()
	testPath := filepath.Join(configDir, "token_store.json")

	tokenStore := &File{path: testPath}

	authInfo, err := tokenStore.readContents()
	require.NoError(t, err)
	require.NotNil(t, authInfo)

	testToken := &oauth2.Token{
		AccessToken:  "foo_access_token",
		TokenType:    "Bearer",
		RefreshToken: "foo_refresh_token",
		Expiry:       time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	authInfo.Tokens["foo"] = testToken

	err = tokenStore.writeContents(authInfo)
	assert.NoError(t, err)

	authInfo, err = tokenStore.readContents()
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.Len(t, authInfo.Tokens, 1)
	assert.Equal(t, testToken, authInfo.Tokens["foo"])
}

func TestTokenOverwrite(t *testing.T) {
	configDir := t.TempDir()
	testPath := filepath.Join(configDir, "token_store.json")

	tokenStore := &File{path: testPath}

	authInfo, err := tokenStore.readContents()
	require.NoError(t, err)
	require.NotNil(t, authInfo)

	// Write token A to the token storage, and verify it can be read back
	testToken := &oauth2.Token{
		AccessToken:  "foo_access_token",
		TokenType:    "Bearer",
		RefreshToken: "foo_refresh_token",
		Expiry:       time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	authInfo.Tokens["foo"] = testToken

	err = tokenStore.writeContents(authInfo)
	assert.NoError(t, err)

	authInfo, err = tokenStore.readContents()
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.Len(t, authInfo.Tokens, 1)
	assert.Equal(t, testToken, authInfo.Tokens["foo"])

	// Write token B to the token storage, and verify that it overwrites what
	// was previously in token storage.
	testToken = &oauth2.Token{
		AccessToken:  "bar_access_token",
		TokenType:    "Bearer",
		RefreshToken: "bar_refresh_token",
		Expiry:       time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	delete(authInfo.Tokens, "foo")
	authInfo.Tokens["bar"] = testToken

	err = tokenStore.writeContents(authInfo)
	assert.NoError(t, err)

	authInfo, err = tokenStore.readContents()
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.Len(t, authInfo.Tokens, 1)
	assert.Equal(t, testToken, authInfo.Tokens["bar"])
}
