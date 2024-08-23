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
	"fmt"
	"io/fs"

	"golang.org/x/oauth2"
)

type multiBackendNotFoundError struct {
	backendsCount int
}

func (m *multiBackendNotFoundError) Error() string {
	return fmt.Sprintf("token for cluster not found after trying %d token storage backends", m.backendsCount)
}

func (m *multiBackendNotFoundError) Is(err error) bool {
	return err == fs.ErrNotExist
}

// Fallback composes multiple backends into a single backend that:
//   - delegates Store() operations to a single specific backend
//   - delegates Load() operations to each backend of a list in turn, returning
//     the token from the first backend to succeed
//   - delegates Delete() operations to all backends
type Fallback struct {
	backends     []LoadStorer
	storeBackend LoadStorer
}

var _ LoadStorer = (*Fallback)(nil)

// NewFallback returns a backend that delegates Store() operations to
// `storeBackend` and Load()/Delete() operations to `backends` (see docs for
// Fallback). `storeBackend` should be repeated as an element of `backends` if
// it should be used for Load()/Delete() operations (which is the common case),
// though it does not need to be the first element.
func NewFallback(storeBackend LoadStorer, backends ...LoadStorer) LoadStorer {
	return &Fallback{
		storeBackend: storeBackend,
		backends:     backends,
	}
}

// Load tries to load a token from each of `backends`, returning the first
// successful response, or all the resulting errors.
func (f *Fallback) Load(cluster string) (*oauth2.Token, error) {
	var errs []error
	for _, backend := range f.backends {
		token, err := backend.Load(cluster)
		if err == nil {
			return token, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("failed to load token from %d backend(s): %w", len(f.backends), errors.Join(errs...))
}

func (f *Fallback) Store(cluster string, token *oauth2.Token) error {
	return f.storeBackend.Store(cluster, token)
}

// Delete attempts to delete credentials for the named cluster from every
// `backend` (but not `storeBackend` explicitly, which should also be present in
// the list of all backends).
//
// If any delete succeeded, then the entire operation is successful.  Otherwise,
// if all errors are "not found", an error that compares to `fs.ErrNotFound` is
// returned.  Otherwise, one of the errors could be a backend where the token
// was found but not successfully deleted; these errors are propagated as-is.
func (f *Fallback) Delete(cluster string) error {
	var errs []error
	// Don't bother to delete from storeBackend, which should also be present in
	// loadBackends
	for _, backend := range f.backends {
		errs = append(errs, backend.Delete(cluster))
	}

	var nonNotFoundErrs []error
	for _, err := range errs {
		if err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			nonNotFoundErrs = append(nonNotFoundErrs, err)
		}
	}
	if err := errors.Join(nonNotFoundErrs...); err != nil {
		return fmt.Errorf("failed to delete token from %d backend(s): %w", len(f.backends), err)
	}
	return &multiBackendNotFoundError{backendsCount: len(f.backends)}
}
