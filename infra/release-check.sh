#!/usr/bin/env bash

# Copyright 2024 EngFlow Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o nounset -o pipefail -o errexit
[[ "${SCRIPT_DEBUG:-"off"}" == "on" ]] && set -o xtrace

if [[ -z "${RELEASE_VERSION:-}" ]]; then
  echo >&2 "RELEASE_VERSION not set"
  exit 1
fi

# Taken from https://semver.org/, with a `v` prepended
readonly SEMVER_REGEX='^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-((0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?$'

# Supplied version string must follow semver
if ! grep --quiet --extended-regexp "${SEMVER_REGEX}" <<<${RELEASE_VERSION}; then
  echo "Supplied version string '${RELEASE_VERSION}' does not follow semver; exiting"
  exit 1
fi

# If this is a release version (not a prerelease), the commit must be on main or
# the correct release branch (e.g., release/v1.2). This constraint doesn't apply
# to prereleases so we can test this workflow.
if [[ "${RELEASE_VERSION}" != *-* ]]; then
  readonly EXPECTED_RELEASE_BRANCH="$(sed --regexp-extended 's|(^v[0-9]+\.[0-9]+)\..*$|release/\1|' <<<${RELEASE_VERSION})"
  if ! git branch \
    --contains "$(git rev-parse HEAD)" \
    | grep --quiet --extended-regexp "main|${EXPECTED_RELEASE_BRANCH}"; then
      echo "Commit $(git rev-parse HEAD) is not on main or release branch ${EXPECTED_RELEASE_BRANCH}; exiting"
      exit 1
  fi
fi
