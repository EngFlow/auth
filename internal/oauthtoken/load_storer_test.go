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
	"io/fs"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var testLoadStorers = []struct {
	name          string
	newLoadStorer func(t *testing.T) LoadStorer
}{
	{
		"keyring",
		func(*testing.T) LoadStorer { return &Keyring{username: "jmcclane"} },
	},
	{
		"file",
		func(t *testing.T) LoadStorer {
			dir := t.TempDir()
			ts, err := NewFileTokenStore(dir)
			require.NoError(t, err)
			return ts
		},
	},
}

func TestTokenRoundTrip(t *testing.T) {
	for _, impl := range testLoadStorers {
		t.Run(impl.name, func(t *testing.T) {
			store := impl.newLoadStorer(t)
			cluster := "nakatomiplaza.cluster.engflow.com"
			token := &oauth2.Token{
				AccessToken: uuid.New().String(),
			}
			_, gotErr := store.Load(cluster)
			require.ErrorIs(t, gotErr, fs.ErrNotExist)

			gotErr = store.Store(cluster, token)
			require.NoError(t, gotErr)

			gotToken, gotErr := store.Load(cluster)
			require.NoError(t, gotErr)
			assert.Equal(t, gotToken, token)

			gotErr = store.Delete(cluster)
			require.NoError(t, gotErr)

			_, gotErr = store.Load(cluster)
			require.ErrorIs(t, gotErr, fs.ErrNotExist)

			gotErr = store.Delete(cluster)
			require.NoError(t, gotErr)
		})
	}
}
