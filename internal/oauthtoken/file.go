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
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
)

// FileStore persists tokens in JSON files in a directory, one file per
// token. The tokens are stored unecrypted. This implementation may be used
// when Keyring cannot be used, for example, in a CI environment when there is
// no encrypted keyring.
type FileStore struct {
	dir string
}

var _ LoadStorer = (*FileStore)(nil)

func NewFileTokenStore(dir string) (*FileStore, error) {
	// Create parent directories with restrictive permissions (0700) rather
	// than 0777. Go applies these bits before the process umask, so a
	// permissive umask with 0777 could leave parents writable by other local
	// users, enabling path-replacement attacks on a shared host.
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, fmt.Errorf("creating parent of token directory: %w", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("creating token directory: %w", err)
		}
		// The path already exists. Do not blindly trust it: another local
		// user could have pre-created a symbolic link or other object at this
		// path to redirect or observe subsequent token-file operations.
		// Verify it is a real directory owned by us and not accessible to
		// group or other users.
		if err := checkTokenDir(dir); err != nil {
			return nil, fmt.Errorf("validating existing token directory: %w", err)
		}
	}
	return &FileStore{dir: dir}, nil
}

// checkTokenDir verifies that the token directory at dir is a regular
// directory (not a symbolic link or other filesystem object), is owned by the
// current user, and is not writable by group or other users. Group/other
// write access is what would allow another local user to replace the
// directory or its contents; token files themselves are written with mode
// 0600.
func checkTokenDir(dir string) error {
	// Use Lstat so that a symbolic link is reported as a symlink rather than
	// followed to its target.
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	mode := info.Mode()
	if mode&fs.ModeSymlink != 0 {
		return fmt.Errorf("%q is a symbolic link, not a directory", dir)
	}
	if !mode.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	if perm := mode.Perm(); perm&0022 != 0 {
		return fmt.Errorf("%q is writable by group or other users (mode %o)", dir, perm)
	}
	if err := checkOwnedByCurrentUser(dir, info); err != nil {
		return err
	}
	return nil
}

func (f *FileStore) Load(cluster string) (_ *oauth2.Token, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("loading token for cluster %q: %w", cluster, err)
		}
	}()

	name, err := tokenFileName(cluster)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	data, err := root.ReadFile(name)
	if err != nil {
		return nil, err
	}
	token := new(oauth2.Token)
	if err := json.Unmarshal(data, token); err != nil {
		return nil, err
	}
	return token, nil
}

func (f *FileStore) Store(cluster string, token *oauth2.Token) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("storing token for cluster %q: %w", cluster, err)
		}
	}()

	name, err := tokenFileName(cluster)
	if err != nil {
		return err
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		return err
	}
	defer root.Close()

	return root.WriteFile(name, data, 0600)
}

func (f *FileStore) Delete(cluster string) error {
	name, err := tokenFileName(cluster)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.Remove(name); errors.Is(err, fs.ErrNotExist) {
		return err
	} else if err != nil {
		return fmt.Errorf("removing token for cluster %q: %w", cluster, err)
	}
	return nil
}

// tokenFileName validates that a cluster key can be used directly as the name
// of a token file within the store directory, and returns that name.
//
// Token files have always been named after the (bare host) cluster key, one
// file per cluster directly inside the store directory. A legitimate host —
// with or without a port — is a single path element and passes unchanged, so
// existing token files remain readable. Any key that would resolve to a
// different directory (because it contains a path separator, a ".." segment,
// is absolute, or is otherwise not a single "clean" path element) is rejected.
//
// This is the first line of defense; os.Root additionally enforces containment
// at the operating-system level for every read, write, and delete, so a key
// that slipped past this check still cannot escape the store directory.
func tokenFileName(cluster string) (string, error) {
	if cluster == "" ||
		cluster == "." ||
		cluster == ".." ||
		strings.ContainsRune(cluster, '/') ||
		strings.ContainsRune(cluster, filepath.Separator) ||
		filepath.Clean(cluster) != cluster {
		return "", fmt.Errorf("invalid cluster identifier %q: must be a single path element", cluster)
	}
	return cluster, nil
}
