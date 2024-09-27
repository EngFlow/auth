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

if [[ -z "${OS:-}" ]]; then
  echo >&2 "OS not set"
  exit 1
fi
if [[ -z "${RELEASE_VERSION:-}" ]]; then
  echo >&2 "RELEASE_VERSION not set"
  exit 1
fi

case "${OS}" in
macos)
  TARGETS=(
    //cmd/engflow_auth:engflow_auth_macos_arm64
    //cmd/engflow_auth:engflow_auth_macos_x64
  )
  ;;
linux)
  TARGETS=(
    //cmd/engflow_auth:engflow_auth_linux_arm64
    //cmd/engflow_auth:engflow_auth_linux_x64
  )
  ;;
windows)
  TARGETS=(
    //cmd/engflow_auth:engflow_auth_windows_x64
  )
  ;;
esac

mkdir _out
BUILD_RELEASE_VERSION="${RELEASE_VERSION}" \
    bazel build \
    --config=release \
    --
    "${TARGETS[@]}"

# TODO(REC-55): sign and notarize binaries on macOS, Windows

for target in "${TARGETS[@]}"; do
  cp "$(bazel cquery --output=files "${target}")" _out/
done
