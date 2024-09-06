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

# logout.sh removes a stored credential for a remote execution service.
# It should be run in CI after all bazel commands.

set -o nounset -o pipefail -o errexit
[[ "${SCRIPT_DEBUG:-"off"}" == "on" ]] && set -o xtrace

if [[ -z "${CLUSTER_HOST:-}" ]]; then
  echo "CLUSTER_HOST not set"
  exit 1
fi
if [[ -z "${OS:-}" ]]; then
  echo "OS not set"
  exit 1
fi

readonly TOOLS_DIR=$(pwd)/_tools
if [[ "${OS}" == "windows" ]]; then
  readonly ENGFLOW_AUTH_PATH="${TOOLS_DIR}/engflow_auth.exe"
else
  readonly ENGFLOW_AUTH_PATH="${TOOLS_DIR}/engflow_auth"
fi

"${ENGFLOW_AUTH_PATH}" logout "${CLUSTER_HOST}"
