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
	"io/fs"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// FakeTokenStore is a test implementation of LoadStorer that stores tokens in
// memory instead of the system keychain.
type FakeTokenStore struct {
	Tokens map[string]*oauth2.Token

	// Error values to be returned by Load, Store, and Delete, if not nil.
	LoadErr, StoreErr, DeleteErr error

	// Value to panic with in Load, Store, and Delete, if not nil.
	// Used to test that a method is NOT called.
	PanicValue any
}

var _ LoadStorer = (*FakeTokenStore)(nil)

func NewFakeTokenStore() *FakeTokenStore {
	return &FakeTokenStore{
		Tokens: make(map[string]*oauth2.Token),
	}
}

func (f *FakeTokenStore) Load(cluster string) (*oauth2.Token, error) {
	if f.PanicValue != nil {
		panic(f.PanicValue)
	}
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
	if f.PanicValue != nil {
		panic(f.PanicValue)
	}
	if f.StoreErr != nil {
		return f.StoreErr
	}
	f.Tokens[cluster] = token
	return nil
}

func (f *FakeTokenStore) Delete(cluster string) error {
	if f.PanicValue != nil {
		panic(f.PanicValue)
	}
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	if _, ok := f.Tokens[cluster]; !ok {
		return fs.ErrNotExist
	}
	delete(f.Tokens, cluster)
	return nil
}

func (f *FakeTokenStore) WithToken(cluster string, token *oauth2.Token) *FakeTokenStore {
	f.Tokens[cluster] = token
	return f
}

func (f *FakeTokenStore) WithTokenForSubject(cluster, subject string) *FakeTokenStore {
	return f.WithToken(cluster, NewFakeTokenForSubject(subject))
}

func (f *FakeTokenStore) WithLoadErr(err error) *FakeTokenStore {
	f.LoadErr = err
	return f
}

func (f *FakeTokenStore) WithStoreErr(err error) *FakeTokenStore {
	f.StoreErr = err
	return f
}

func (f *FakeTokenStore) WithDeleteErr(err error) *FakeTokenStore {
	f.DeleteErr = err
	return f
}

func (f *FakeTokenStore) WithPanic(value any) *FakeTokenStore {
	f.PanicValue = value
	return f
}

func NewFakeTokenForSubject(subject string) *oauth2.Token {
	now := time.Now()
	expiry := now.Add(time.Hour)
	payload := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "engflow unit tests",
		Subject:   subject,
		Audience:  nil,
		ExpiresAt: jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
	})
	tokenStr, err := payload.SignedString([]byte("some signing key"))
	if err != nil {
		panic(err)
	}
	return &oauth2.Token{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		Expiry:      expiry,
	}
}
