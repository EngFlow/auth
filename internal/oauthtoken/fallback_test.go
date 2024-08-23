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
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

var (
	testCluster = "nakatomiplaza.cluster.example.com"
	testToken   = &oauth2.Token{AccessToken: "quarterback_is_toast"}
)

func TestFallbackLoad(t *testing.T) {
	testCases := []struct {
		desc     string
		backendA LoadStorer
		backendB LoadStorer

		wantErr string
	}{
		{
			desc:     "first backend has token",
			backendA: NewFakeTokenStore().WithToken(testCluster, testToken),
			backendB: NewFakeTokenStore().WithToken(testCluster, testToken),
		},
		{
			desc:     "non-first backend has token",
			backendA: NewFakeTokenStore().WithLoadErr(fs.ErrNotExist),
			backendB: NewFakeTokenStore().WithToken(testCluster, testToken),
		},
		{
			desc:     "first backend failure",
			backendA: NewFakeTokenStore().WithLoadErr(errors.New("welcome to the party, pal!")),
			backendB: NewFakeTokenStore().WithToken(testCluster, testToken),
		},
		{
			desc:     "token not found",
			backendA: NewFakeTokenStore().WithLoadErr(fs.ErrNotExist),
			backendB: NewFakeTokenStore().WithLoadErr(fs.ErrNotExist),
			wantErr:  fs.ErrNotExist.Error(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			backend := NewFallback(nil, tc.backendA, tc.backendB)

			got, gotErr := backend.Load(testCluster)

			if tc.wantErr != "" {
				assert.ErrorContains(t, gotErr, tc.wantErr)
			} else {
				assert.NoError(t, gotErr)
			}
			if gotErr != nil {
				return
			}

			assert.Equal(t, testToken, got)
		})
	}
}

func TestFallbackStore(t *testing.T) {
	testCases := []struct {
		desc    string
		backend LoadStorer

		wantErr string
	}{
		{
			desc:    "success",
			backend: NewFakeTokenStore(),
		},
		{
			desc:    "failure",
			backend: NewFakeTokenStore().WithStoreErr(errors.New("we're gonna need some more FBI guys")),
			wantErr: "we're gonna need some more FBI guys",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			backend := NewFallback(tc.backend)

			gotErr := backend.Store(testCluster, testToken)

			if tc.wantErr != "" {
				assert.ErrorContains(t, gotErr, tc.wantErr)
			} else {
				assert.NoError(t, gotErr)
			}
		})
	}
}

func TestFallbackDelete(t *testing.T) {
	testCases := []struct {
		desc     string
		backendA LoadStorer
		backendB LoadStorer
		backendC LoadStorer

		wantErr string
	}{
		{
			desc:     "success in one backend",
			backendA: NewFakeTokenStore(),
			backendB: NewFakeTokenStore().WithToken(testCluster, testToken),
			backendC: NewFakeTokenStore(),
		},
		{
			desc:     "success in multiple backends",
			backendA: NewFakeTokenStore().WithToken(testCluster, testToken),
			backendB: NewFakeTokenStore().WithToken(testCluster, testToken),
			backendC: NewFakeTokenStore().WithToken(testCluster, testToken),
		},
		{
			desc:     "not found in all backends",
			backendA: NewFakeTokenStore(),
			backendB: NewFakeTokenStore(),
			backendC: NewFakeTokenStore(),
			wantErr:  "not found after trying 3 token storage backends",
		},
		{
			desc:     "single backend failure",
			backendA: NewFakeTokenStore(),
			backendB: NewFakeTokenStore(),
			backendC: NewFakeTokenStore().WithToken(testCluster, testToken).WithDeleteErr(errors.New("does it sound like i'm ordering a pizza?")),
			wantErr:  "does it sound like i'm ordering a pizza?",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			backend := NewFallback(tc.backendB, tc.backendA, tc.backendB, tc.backendC)

			gotErr := backend.Delete(testCluster)

			if tc.wantErr != "" {
				assert.ErrorContains(t, gotErr, tc.wantErr)
			} else {
				assert.NoError(t, gotErr)
			}
		})
	}
}
