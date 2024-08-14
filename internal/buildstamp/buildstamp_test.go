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

// Package buildstamp exports build metadata values that may be optionally set
// by the build system, for runtime inspection. The primary usecase is for
// identifying application provenance (e.g. what branch, user built the code).
package buildstamp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	testCases := []struct {
		desc        string
		vars        Vars
		wantVersion string
		wantErr     string
	}{
		{
			desc: "stamped official build",
			vars: Vars{
				ReleaseVersion: "v1.0.2",
				SourceBranch:   "main",
				SourceRevision: "abcdefbutnotg",
				IsClean:        true,
				IsOfficial:     true,
				BuildTimestamp: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			wantVersion: "v1.0.2",
		},
		{
			desc:    "unstamped build",
			vars:    emptyValues,
			wantErr: ErrStampingDisabled.Error(),
		},
		{
			desc: "unofficial due to dirty repo",
			vars: Vars{
				ReleaseVersion: unknown,
				SourceBranch:   "main",
				SourceRevision: "abcdefbutnotg",
				IsClean:        false,
				IsOfficial:     false,
				BuildTimestamp: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			wantVersion: "v0.0.0-20240102030405-abcdefbutnot+dirty",
		},
		{
			desc: "unofficial due to wrong branch",
			vars: Vars{
				ReleaseVersion: unknown,
				SourceBranch:   "some_dev_branch",
				SourceRevision: "abcdefbutnotg",
				IsClean:        true,
				IsOfficial:     false,
				BuildTimestamp: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			wantVersion: "v0.0.0-20240102030405-abcdefbutnot",
		},
		{
			desc: "unofficial due to unknown reason",
			vars: Vars{
				ReleaseVersion: "v1.0.2",
				SourceBranch:   "main",
				SourceRevision: "abcdefbutnotg",
				IsClean:        true,
				IsOfficial:     false,
				BuildTimestamp: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			wantVersion: "v0.0.0-20240102030405-abcdefbutnot",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, gotErr := tc.vars.GetVersion()
			t.Logf("got: %v; gotErr: %v", got, gotErr)

			if tc.wantErr != "" {
				assert.ErrorContains(t, gotErr, tc.wantErr)
			} else {
				assert.NoError(t, gotErr)
			}

			if gotErr != nil {
				return
			}

			assert.Equal(t, tc.wantVersion, got)
		})
	}
}
