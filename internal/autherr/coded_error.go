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

package autherr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	CodeUnknownError      = 1
	CodeUnknownSubcommand = 2 // Also happens to be used for flag.Parse errors, which is fitting
	CodeUnimplemented     = 3
	CodeBadParams         = 4
	CodeAuthFailure       = 5
	CodeTokenStoreFailure = 6
	CodeReauthRequired    = 7
)

var UnexpectedHTML = errors.New("request to JSON API returned HTML unexpectedly")

// CodedError wraps an error with an integer code that can be used as e.g. a
// return code from an application.
type CodedError struct {
	Code int
	Err  error
}

func (e *CodedError) Error() string {
	return e.Err.Error()
}

func (e *CodedError) ExitCode() int {
	return e.Code
}

func CodedErrorf(code int, format string, args ...any) error {
	return &CodedError{
		Code: code,
		Err:  fmt.Errorf(format, args...),
	}
}

func ReauthRequired(cluster string) error {
	const reauthMessage = "Missing/invalid/expired credentials for cluster: %s\n" +
		"Please refresh credentials by running:\n\n\t" +
		"%s login %s\n"
	cmdPath := filepath.ToSlash(os.Args[0])
	return CodedErrorf(CodeReauthRequired, reauthMessage, cluster, cmdPath, cluster)
}
