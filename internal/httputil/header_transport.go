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

// Package httputil provides additional types/helpers for HTTP communication.
package httputil

import "net/http"

// HeaderInsertingTransport wraps an http.RoundTripper and inserts headers into
// the request before propagating it to the underlying implementation.
type HeaderInsertingTransport struct {
	// Transport is the underlying transport actually performing requests.
	Transport http.RoundTripper
	// Headers specify the headers to add on each request. These headers will
	// override existing headers on the request with the same name; headers on
	// the request not mentioned here are not modified.
	Headers http.Header
}

func (t *HeaderInsertingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request so the original is not modified
	req = req.Clone(req.Context())

	for k := range t.Headers {
		req.Header.Del(k)
	}
	for k, vals := range t.Headers {
		for _, val := range vals {
			req.Header.Add(k, val)
		}
	}
	return t.Transport.RoundTrip(req)
}
