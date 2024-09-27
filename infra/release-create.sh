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

readonly ARTIFACTS_DIR=_out
readonly GH_CLI_DIR="$(mktemp -d -t 'gh_cli_XXXXXXXX')"
readonly GH_CLI_URL='https://storage.googleapis.com/engflow-tools-public/github.com/cli/cli/releases/download/v2.52.0/gh_2.52.0_linux_amd64.tar.gz'
readonly GH_CLI_EXPECTED_SHA256='3ea6ed8b2585f406a064cecd7e1501e58f56c8e7ca764ae1f3483d1b8ed68826'
readonly GH_CLI="${GH_CLI_DIR}/bin/gh"

function cleanup {
  echo "[START]  Temp directory cleanup"
  rm -rf "${GH_CLI_DIR}"
  echo "[FINISH] Temp directory cleanup"
}
trap 'cleanup' EXIT

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

if [[ "${DRY_RUN}" == true ]]; then
  echo "[SKIP]   Creating release"
  exit 0
fi
RELEASE_ARGS=()
for file in $(find "${ARTIFACTS_DIR}" -type f); do
  os=$(echo "$file" | sed -E -e 's,^.*_([^_]*)_[^_]*$,\1,' -e 's,macos,macOS,' -e 's,windows,Windows,')
  arch=$(echo "$file" | sed -E -e 's,^.*_([^_]*),\1,')
  arg="${file}#engflow_auth (${os}, ${arch})"
  RELEASE_ARGS+=("${arg}")
done
"${GH_CLI}" release create \
  "${RELEASE_VERSION}" \
  --generate-notes \
  "${RELEASE_ARGS[@]}"
echo "[FINISH] Creating release"
