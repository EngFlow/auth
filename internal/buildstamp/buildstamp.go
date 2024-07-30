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
	"fmt"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type Vars struct {
	SourceBranch   string
	SourceRevision string
	IsClean        bool
	IsOfficial     bool
	BuildTimestamp time.Time
}

const (
	unknown = "<unknown>"

	gitStatusClean = "clean"
	gitStatusDirty = "modified"
)

var (
	gitBranch           = unknown
	gitSha              = unknown
	gitSourceTreeStatus = unknown
	buildTimestamp      = unknown

	Values      Vars
	emptyValues Vars

	gitOfficialBranchRe = regexp.MustCompile(`main|release/v[0-9]+\.[0-9]+`)
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		// Binary was built as part of normal Go build; fill in values from
		// BuildInfo.Settings. Keys currently used are documented here:
		// https://pkg.go.dev/runtime/debug#BuildSetting

		if revision, ok := lookupBuildSetting(info, "vcs.revision"); ok {
			Values.SourceRevision = revision
		}

		if modified, _ := lookupBuildSetting(info, "vcs.modified"); ok {
			Values.IsClean = modified == "false"

			// Go tooling doesn't embed the branch name, so we can't perform a
			// thorough check for "official" builds here; this one is
			// best-effort, with the data available.
			Values.SourceBranch = unknown
			Values.IsOfficial = modified == "false"
		}

		// This isn't technically the build timestamp, but rather the timestamp
		// of the most recent VCS change.
		if timeStr, ok := lookupBuildSetting(info, "vcs.modified"); ok {
			if ts, err := time.Parse(time.RFC3339, timeStr); err != nil {
				Values.BuildTimestamp = ts
			}
		}
	} else {
		// Binary was built via bazel; use globals that have been possibly
		// modified via `x_defs` BUILD target attribute

		if gitBranch == unknown && gitSha == unknown {
			// Basic values aren't initialized by the linker; assume stamping was
			// not enabled and leave Vars as the zero-value to make this clear.
			return
		}
		// Assume stamping is enabled, and initialize Vars accordingly.

		Values.SourceBranch = gitBranch
		Values.SourceRevision = gitSha
		Values.IsClean = gitSourceTreeStatus == gitStatusClean
		Values.IsOfficial = gitSourceTreeStatus == gitStatusClean && gitOfficialBranchRe.Match([]byte(gitBranch))

		if ts, err := strconv.ParseInt(buildTimestamp, 10, 64); err == nil {
			Values.BuildTimestamp = time.Unix(ts, 0)
		}
	}
}

func lookupBuildSetting(info *debug.BuildInfo, name string) (string, bool) {
	for _, setting := range info.Settings {
		if setting.Key == name {
			return setting.Value, true
		}
	}
	return "", false
}

func (v Vars) String() string {
	if v == emptyValues {
		return "build metadata is unavailable (build with bazel's `--stamp` flag to enable)"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "build time: %v\n", v.BuildTimestamp)
	fmt.Fprintf(&sb, "official build: %v\n", v.IsOfficial)
	fmt.Fprintf(&sb, "build branch: %s\n", v.SourceBranch)
	fmt.Fprintf(&sb, "build revision: %s\n", v.SourceRevision)
	fmt.Fprintf(&sb, "clean build: %v\n", v.IsClean)
	return sb.String()
}
