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

if [[ "$#" -ne 1 ]]; then
  echo "Want 1 argument; got $# arguments"
  exit 1
fi

# Taken from https://semver.org/, with a `v` prepended
readonly SEMVER_REGEX='^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-((0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?$'
readonly RELEASE_VERSION="$1"
readonly GH_CLI_URL='https://storage.googleapis.com/engflow-tools-public/github.com/cli/cli/releases/download/v2.52.0/gh_2.52.0_linux_amd64.tar.gz'
readonly GH_CLI_EXPECTED_SHA256='3ea6ed8b2585f406a064cecd7e1501e58f56c8e7ca764ae1f3483d1b8ed68826'

echo "[START]  Release name checks"
# Supplied version string must follow semver
if ! grep --quiet --extended-regexp "${SEMVER_REGEX}" <<<${RELEASE_VERSION}; then
  echo "Supplied version string '${RELEASE_VERSION}' does not follow semver; exiting"
  exit 1
fi
echo "[FINISH] Release name checks"

function cleanup {
  echo "[START]  Temp directory cleanup"
  rm -rf "${ARTIFACTS_DIR}"
  rm -rf "${GH_CLI_DIR}"
  echo "[FINISH] Temp directory cleanup"
}

ARTIFACTS_DIR="$(mktemp -d -t 'engflow_auth_release_XXXXXXXX')"

# TODO(CUS-353): Remove this after installing Github CLI in the self-hosted
# environment (run via Docker?)
echo "[START]  Downloading gh CLI"
readonly GH_CLI_DIR="$(mktemp -d -t 'gh_cli_XXXXXXXX')"
curl --silent --location "${GH_CLI_URL}" \
  | tee >(sha256sum - > "${GH_CLI_DIR}/archive_checksum.txt") \
  | tar \
      -C "${GH_CLI_DIR}" \
      --strip-components 1 \
      -xzf \
      -
trap 'cleanup' EXIT
readonly GH_CLI="${GH_CLI_DIR}/bin/gh"
readonly GH_CLI_ACTUAL_SHA256="$(cat ${GH_CLI_DIR}/archive_checksum.txt | awk '{ print $1 }')"
if [[ "${GH_CLI_ACTUAL_SHA256}" != "${GH_CLI_EXPECTED_SHA256}" ]]; then
    echo "SHA256 for Github CLI tarball ${GH_CLI_ACTUAL_SHA256} doesn't match expected value ${GH_CLI_ACTUAL_SHA256}; exiting"
    exit 1
fi
echo "[FINISH] Downloading gh CLI"

# If this is a release version (not a prerelease), the commit must be on main or
# the correct release branch (e.g., release/v1.2). This constraint doesn't apply
# to prereleases so we can test this workflow.
echo "[START]  Release branch checks"
if [[ "${RELEASE_VERSION}" != *-* ]]; then
  readonly EXPECTED_RELEASE_BRANCH="$(sed --regexp-extended 's|(^v[0-9]+\.[0-9]+)\..*$|release/\1|' <<<${RELEASE_VERSION})"
  if ! git branch \
    --contains "$(git rev-parse HEAD)" \
    | grep --quiet --extended-regexp "main|${EXPECTED_RELEASE_BRANCH}"; then
      echo "Commit $(git rev-parse HEAD) is not on main or release branch ${EXPECTED_RELEASE_BRANCH}; exiting"
      exit 1
  fi
fi
echo "[FINISH] Release branch checks"

# Build release artifacts
echo "[START]  Building artifacts"
BUILD_RELEASE_VERSION="${RELEASE_VERSION}" \
    bazel build \
    --config=release \
    -- \
    //:release_artifacts
echo "[FINISH] Building artifacts"

# Stage release artifacts - this works around an artifact naming uniqueness
# issue with Github release artifacts. Namely - once we follow bazel symlinks
# (e.g. via `realpath`, because gh CLI won't follow symlinks), binaries for UNIX
# platforms will have the same basename. Github will infer an artifact name from
# basename, and require these inferred names to be unique. Staging in a
# directory allows us to manually ensure basename uniqueness.
#
# This is brittle w.r.t. adding new artifacts; if we can find a smarter way to
# build artifacts with unique basenames under bazel-bin after symlink
# resolution, we may be able to drop this staging step and the corresponding
# temp dir.
echo "[START]  Staging artifacts"
cp \
  bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_linux_arm64 \
  "${ARTIFACTS_DIR}/engflow_auth_linux_arm64"

cp \
  bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_linux_x64 \
  "${ARTIFACTS_DIR}/engflow_auth_linux_x64"

cp \
  bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_macos_arm64 \
  "${ARTIFACTS_DIR}/engflow_auth_macos_arm64"

cp \
  bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_macos_x64 \
  "${ARTIFACTS_DIR}/engflow_auth_macos_x64"

cp \
  bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_windows_x64 \
  "${ARTIFACTS_DIR}/engflow_auth_windows_x64"
echo "[FINISH] Staging artifacts"

# Create release
if [[ "${DRY_RUN}" == true ]]; then
  echo "[SKIP]   Creating release"
  exit 0
fi
echo "[START]  Creating release"
${GH_CLI} release create \
    "${RELEASE_VERSION}" \
    --generate-notes \
    "${ARTIFACTS_DIR}/engflow_auth_linux_arm64#engflow_auth (Linux, arm64)" \
    "${ARTIFACTS_DIR}/engflow_auth_linux_x64#engflow_auth (Linux, x64)" \
    "${ARTIFACTS_DIR}/engflow_auth_macos_arm64#engflow_auth (macOS, arm64)" \
    "${ARTIFACTS_DIR}/engflow_auth_macos_x64#engflow_auth (macOS, x64)" \
    "${ARTIFACTS_DIR}/engflow_auth_windows_x64#engflow_auth (Windows, x64)"
echo "[FINISH] Creating release"
