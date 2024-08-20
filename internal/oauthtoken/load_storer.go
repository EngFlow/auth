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
	"golang.org/x/oauth2"
)

// LoadStorer provides access to a token via some backend implementation/policy.
type LoadStorer interface {
	// Load loads a token for a cluster, specified by hostname. It returns
	// fs.ErrNotFound if the token isn't present, or an unspecified non-nil
	// error for any other error conditions.
	Load(cluster string) (*oauth2.Token, error)

	// Store stores a token for a cluster, specified by hostname. It returns an
	// unspecified non-nil error if the operation fails; in this case, the state
	// of the token storage for the specified cluster is not specified (token
	// storage for other clusters is unaffected).
	Store(cluster string, token *oauth2.Token) error

	// Delete deletes a token for a cluster, specified by hostname. It returns
	// fs.ErrNotFound if there is currently no token stored for the specified
	// cluster, or an unspecified non-nil error for any other error conditions
	// (although the storage backend should make a best-effort attempt to delete
	// the token).
	Delete(string) error
}
