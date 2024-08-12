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

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	skipRegexps = []*regexp.Regexp{
		regexp.MustCompile(`^go\.mod$`),
		regexp.MustCompile(`^go\.sum$`),
		regexp.MustCompile(`^LICENSE$`),
		regexp.MustCompile(`^MODULE\.bazel\.lock$`),
		regexp.MustCompile(`^MODULE\.bazel$`),
		regexp.MustCompile(`^README.md$`),
		regexp.MustCompile(`^WORKSPACE$`),
		regexp.MustCompile(`(/|^)BUILD$`),
		regexp.MustCompile(`^\.bazelrc$`),
		regexp.MustCompile(`^\.bazelversion$`),
		regexp.MustCompile(`^\.gitignore$`),
		regexp.MustCompile(`\.bzl$`),
	}
	copyrightRegexp = regexp.MustCompile(`^(#|//) Copyright [0-9-]+ EngFlow Inc\.`)
)

type checkerFunc func(string) bool

// listSourceFiles returns the list of files that git cares about in the current
// commit.
func listSourceFiles(repoRoot string) ([]string, error) {
	cmd := exec.Command("git", "ls-tree", "-r", "--name-only", "HEAD")
	cmd.Dir = repoRoot
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("`git ls-tree` failed: %w", err)
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// filterStrings returns strings in `universe` that don't match any regexps in
// `remove`.
func filterStrings(universe []string, remove []*regexp.Regexp) []string {
	var filtered []string
nextStr:
	for _, s := range universe {
		for _, r := range remove {
			if r.MatchString(s) {
				continue nextStr
			}
		}
		filtered = append(filtered, s)
	}
	return filtered
}

// checkCopyright runs the supplied checker on each line of the file, returning
// an error if the checker never returns true.
func checkCopyright(path string, checker checkerFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if checker(scanner.Text()) {
			return nil
		}
	}
	return fmt.Errorf("%s: missing copyright header", path)
}

func run() error {
	workspaceRoot := os.Getenv("BUILD_WORKSPACE_DIRECTORY")
	if workspaceRoot == "" {
		return fmt.Errorf("$BUILD_WORKSPACE_DIRECTORY is not set; please run this script via `bazel run`")
	}
	srcFiles, err := listSourceFiles(workspaceRoot)
	if err != nil {
		return err
	}

	srcFiles = filterStrings(srcFiles, skipRegexps)

	var errs []error
	for _, f := range srcFiles {
		if err := checkCopyright(filepath.Join(workspaceRoot, f), copyrightRegexp.MatchString); err != nil {
			errs = append(errs, err)
			continue
		}
	}

	if len(errs) == 0 {
		return nil
	}

	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return fmt.Errorf("copyright header check failed:\n%v", errors.Join(errs...))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}
