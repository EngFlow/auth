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

//go:build !unix

package oauthtoken

import "io/fs"

// checkOwnedByCurrentUser is a no-op on platforms where POSIX ownership
// semantics do not apply (e.g. Windows). The directory-type and permission
// checks in checkTokenDir still apply.
func checkOwnedByCurrentUser(dir string, info fs.FileInfo) error {
	return nil
}
