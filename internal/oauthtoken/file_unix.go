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

//go:build unix

package oauthtoken

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkOwnedByCurrentUser verifies that the filesystem object described by
// info at path dir is owned by the user ID of the current process.
func checkOwnedByCurrentUser(dir string, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %q", dir)
	}
	if uid := os.Getuid(); uint64(stat.Uid) != uint64(uid) {
		return fmt.Errorf("%q is owned by uid %d, not the current user (uid %d)", dir, stat.Uid, uid)
	}
	return nil
}
