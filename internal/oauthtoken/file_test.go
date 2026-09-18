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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewFileTokenStore(t *testing.T) {
	t.Run("creates directory tree", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "a", "b", "tokens")
		_, err := NewFileTokenStore(dir)
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
		}
	})

	t.Run("accepts existing well-formed directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "tokens")
		require.NoError(t, os.Mkdir(dir, 0700))
		_, err := NewFileTokenStore(dir)
		require.NoError(t, err)
	})

	t.Run("rejects symlink at token directory path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is restricted on Windows")
		}
		base := t.TempDir()
		target := filepath.Join(base, "target")
		require.NoError(t, os.Mkdir(target, 0700))
		link := filepath.Join(base, "tokens")
		require.NoError(t, os.Symlink(target, link))

		_, err := NewFileTokenStore(link)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symbolic link")
	})

	t.Run("rejects non-directory at token directory path", func(t *testing.T) {
		base := t.TempDir()
		path := filepath.Join(base, "tokens")
		require.NoError(t, os.WriteFile(path, []byte("not a dir"), 0600))

		_, err := NewFileTokenStore(path)
		require.Error(t, err)
	})

	t.Run("rejects group- or other-writable directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permission bits do not apply on Windows")
		}
		dir := filepath.Join(t.TempDir(), "tokens")
		require.NoError(t, os.Mkdir(dir, 0777))
		// os.Mkdir applies the umask, so force the loose bits explicitly.
		require.NoError(t, os.Chmod(dir, 0777))

		_, err := NewFileTokenStore(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "writable")
	})
}

// traversalKeys are cluster identifiers that must never be allowed to resolve
// to a path outside the token store directory. These mirror the values a
// malicious cluster URL or import blob can produce (see sanitizedURL, which
// moves a bare relative value into the URL host).
var traversalKeys = []string{
	"../../../../../escaped/token",
	"..",
	".",
	"",
	"sub/token",
	"a/../../b",
	"/etc/passwd",
	"/absolute/path",
}

func TestFileStoreRejectsPathTraversal(t *testing.T) {
	// A sentinel file living next to the store directory stands in for any
	// user-accessible file an attacker might try to read, overwrite, or delete.
	base := t.TempDir()
	dir := filepath.Join(base, "tokens")
	store, err := NewFileTokenStore(dir)
	require.NoError(t, err)

	sentinelRel := filepath.Join("..", "sentinel")
	sentinelPath := filepath.Join(dir, sentinelRel)
	const sentinelContent = "important-user-data"

	for _, key := range traversalKeys {
		t.Run(key, func(t *testing.T) {
			require.NoError(t, os.WriteFile(sentinelPath, []byte(sentinelContent), 0600))

			_, loadErr := store.Load(key)
			require.Error(t, loadErr, "Load must reject traversal key")

			storeErr := store.Store(key, &oauth2.Token{AccessToken: "attacker-controlled"})
			require.Error(t, storeErr, "Store must reject traversal key")

			deleteErr := store.Delete(key)
			require.Error(t, deleteErr, "Delete must reject traversal key")

			// The sentinel file must be untouched by any of the operations.
			got, err := os.ReadFile(sentinelPath)
			require.NoError(t, err, "sentinel file must still exist")
			assert.Equal(t, sentinelContent, string(got), "sentinel file must be unmodified")
		})
	}
}

func TestTokenFileName(t *testing.T) {
	// Legitimate cluster hosts (with or without a port) are single path
	// elements and must pass through unchanged for backwards compatibility.
	for _, valid := range []string{
		"nakatomiplaza.cluster.engflow.com",
		"cluster.example.com",
		"cluster.example.com:8080",
	} {
		name, err := tokenFileName(valid)
		require.NoErrorf(t, err, "expected %q to be accepted", valid)
		assert.Equal(t, valid, name)
	}

	for _, invalid := range traversalKeys {
		_, err := tokenFileName(invalid)
		assert.Errorf(t, err, "expected %q to be rejected", invalid)
	}
}
