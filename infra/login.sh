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

# login.sh configures the build environment to authenticate with a
# remote execution service. It should be run in CI before any bazel command.
# logout.sh should be run afterward to remove stored credentials.

set -o nounset -o pipefail -o errexit
[[ "${SCRIPT_DEBUG:-"off"}" == "on" ]] && set -o xtrace

if [[ -z "${ARCH:-}" ]]; then
  case "$(uname -m)" in
  aarch64|arm64)
    export ARCH=arm64
    ;;
  x86_64)
    export ARCH=x64
    ;;
  *)
    echo >&2 "ARCH not set, and 'uname -m' returned unknown value $(uname -m)"
    exit 1
  esac
fi
if [[ -z "${CLUSTER_HOST:-}" ]]; then
  echo "CLUSTER_HOST not set"
  exit 1
fi
if [[ -z "${CRED_HELPER_TOKEN:-}" ]]; then
  echo "CRED_HELPER_TOKEN not set"
  exit 1
fi
if [[ -z "${OS:-}" ]]; then
  case "$(uname)" in
  Darwin)
    export OS=macos
    ;;
  Linux)
    export OS=linux
    ;;
  MSYS*)
    export OS=windows
    ;;
  *)
    echo >&2 "OS not set, and 'uname' returned unknown value $(uname)"
    exit 1
  esac
fi

# Download a recent version of engflow_auth to a local directory,
# then use it to import the credential.
readonly ENGFLOW_AUTH_VERSION=v0.0.7
readonly TOOLS_DIR=$(pwd)/_tools
readonly ENGFLOW_AUTH_URL="https://github.com/EngFlow/auth/releases/download/${ENGFLOW_AUTH_VERSION}/engflow_auth_${OS}_${ARCH}"
if [[ "${OS}" == "windows" ]]; then
  # On Windows, ensure engflow_auth has an .exe extension. Use an absolute
  # Windows path with forward slashes (C:/a/b), NOT a cygwin path (/c/a/b),
  # and NOT backslashes (C:\a\b). Bazel only accepts the first form.
  readonly ENGFLOW_AUTH_PATH="$(cygpath --mixed "${TOOLS_DIR}/engflow_auth.exe")"
else
  readonly ENGFLOW_AUTH_PATH="${TOOLS_DIR}/engflow_auth"
fi
mkdir -p "${TOOLS_DIR}"
if ! curl --fail-with-body --location --output "${ENGFLOW_AUTH_PATH}" "${ENGFLOW_AUTH_URL}"; then
  cat "${ENGFLOW_AUTH_PATH}" >&2
  exit 1
fi
chmod +x "${ENGFLOW_AUTH_PATH}"

# Import the credential.
"${ENGFLOW_AUTH_PATH}" import -store=file <<<"${CRED_HELPER_TOKEN}"

# Configure Bazel to use the credential.
cat >.bazelrc.user <<EOF
common --credential_helper=${CLUSTER_HOST}=${ENGFLOW_AUTH_PATH}
EOF
