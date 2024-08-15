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
	"fmt"

	"golang.org/x/oauth2"
)

// FakeTokenStore is a test implementation of LoadStorer that stores tokens in
// memory instead of the system keychain.
type FakeTokenStore struct {
	Tokens                       map[string]*oauth2.Token
	LoadErr, StoreErr, DeleteErr error
}

var _ LoadStorer = (*FakeTokenStore)(nil)

func NewFakeTokenStore() *FakeTokenStore {
	return &FakeTokenStore{
		Tokens: make(map[string]*oauth2.Token),
	}
}

func (f *FakeTokenStore) Load(cluster string) (*oauth2.Token, error) {
	if f.LoadErr != nil {
		return nil, f.LoadErr
	}
	token, ok := f.Tokens[cluster]
	if !ok {
		return nil, fmt.Errorf("%s: token not found", cluster)
	}
	return token, nil
}

func (f *FakeTokenStore) Store(cluster string, token *oauth2.Token) error {
	if f.StoreErr != nil {
		return f.StoreErr
	}
	f.Tokens[cluster] = token
	return nil
}

func (f *FakeTokenStore) Delete(cluster string) error {
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	delete(f.Tokens, cluster)
	return nil
}
