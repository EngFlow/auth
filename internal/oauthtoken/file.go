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
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating token directory: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

func (f *FileStore) Load(cluster string) (_ *oauth2.Token, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("loading token for cluster %s: %w", cluster, err)
		}
	}()

	data, err := os.ReadFile(f.tokenFilePath(cluster))
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
			err = fmt.Errorf("storing token for cluster %s: %w", cluster, err)
		}
	}()

	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return os.WriteFile(f.tokenFilePath(cluster), data, 0600)
}

func (f *FileStore) Delete(cluster string) error {
	if err := os.Remove(f.tokenFilePath(cluster)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing token for cluster %s: %w", cluster, err)
	}
	return nil
}

func (f *FileStore) tokenFilePath(cluster string) string {
	return filepath.Join(f.dir, cluster)
}
