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
