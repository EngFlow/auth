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
	"testing"

	"github.com/EngFlow/auth/internal/autherr"
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

func TestKeyringTokenRoundtrip(t *testing.T) {
	ctx := context.Background()
	testKeyring := &Keyring{
		username: "jmcclane",
	}
	cluster := "nakatomiplaza.cluster.engflow.com"
	token := &oauth2.Token{
		AccessToken: uuid.New().String(),
	}
	_, gotErr := testKeyring.Load(ctx, cluster)
	require.Equal(t, autherr.ReauthRequired(cluster), gotErr)

	gotErr = testKeyring.Store(ctx, cluster, token)
	require.NoError(t, gotErr)

	gotToken, gotErr := testKeyring.Load(ctx, cluster)
	require.NoError(t, gotErr)
	assert.Equal(t, gotToken, token)

	gotErr = testKeyring.Delete(ctx, cluster)
	require.NoError(t, gotErr)

	gotToken, gotErr = testKeyring.Load(ctx, cluster)
	require.Equal(t, autherr.ReauthRequired(cluster), gotErr)
	require.Nil(t, gotToken)
}
