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
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func mustTokenForSubject(t *testing.T, name string) string {
	t.Helper()
	now := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "engflow unit tests",
		Subject:   name,
		Audience:  nil,
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
	})
	tokenStr, err := token.SignedString([]byte("some signing key"))
	require.NoError(t, err)

	return tokenStr
}

func TestTokenCacheWarning(t *testing.T) {
	ctx := context.Background()
	configDir := t.TempDir()
	testPath := filepath.Join(configDir, "token_store.json")
	var testStderr bytes.Buffer
	tokenStore := &CacheAlert{
		impl:   &File{path: testPath},
		stderr: &testStderr,
	}

	testTokenAlice := &oauth2.Token{
		AccessToken: mustTokenForSubject(t, "alice"),
		TokenType:   "Bearer",
	}
	testTokenBob := &oauth2.Token{
		AccessToken: mustTokenForSubject(t, "bob"),
		TokenType:   "Bearer",
	}

	// Storing an initial token should produce no warning
	err := tokenStore.Store(ctx, "default", testTokenAlice)
	require.NoError(t, err)
	assert.Len(t, testStderr.String(), 0)
	err = tokenStore.Store(ctx, "special", testTokenAlice)
	require.NoError(t, err)
	assert.Len(t, testStderr.String(), 0)

	// Storing a token with a different principal for a given cluster should
	// produce a warning
	err = tokenStore.Store(ctx, "default", testTokenBob)
	require.NoError(t, err)
	assert.Contains(t, testStderr.String(), "Login identity has changed")
	assert.Contains(t, testStderr.String(), "bazel shutdown")
	testStderr.Reset()

	// Storing a token with the same principal for a given cluster should
	// produce no warning
	err = tokenStore.Store(ctx, "special", testTokenAlice)
	require.NoError(t, err)
	assert.Len(t, testStderr.String(), 0)
}
