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
if [[ "${OS}" == 'macos' && -z "${APPLE_CERT_BASE64:-}" ]]; then
  echo >&2 "APPLE_CERT_BASE64 not set"
  exit 1
fi
if [[ -z "${RELEASE_VERSION:-}" ]]; then
  echo >&2 "RELEASE_VERSION not set"
  exit 1
fi

install_cert () {
  if [[ "${OS}" != 'macos' ]]; then
    return
  fi
  # Files in $RUNNER_TEMP are automatically removed on completion.
  local p12_path="${RUNNER_TEMP}/build_certificate.p12"
  base64 --decode <<<"${APPLE_CERT_BASE64}" >"${p12_path}"
  local keychain_path="${RUNNER_TEMP}/dev.keychain"
  security create-keychain -p '' "${keychain_path}"
  security set-keychain-settings "${keychain_path}"
  security unlock-keychain -p '' "${keychain_path}"
  security import "${p12_path}" -P '' -A -t cert -f pkcs12 -k "${keychain_path}"
  # Allow productsign to access the identity
  security set-key-partition-list -S apple-tool:,apple:,codesign:,productsign: -s -k '' "${keychain_path}"
  # Overwrite the keychain search list with the new keychain
  security list-keychain -d user -s "${keychain_path}"
  security find-identity -v
}

uninstall_cert () {
  if [[ "${OS}" != 'macos' ]]; then
    return
  fi
  security list-keychains -s ~/Library/Keychains/login.keychain
  security delete-keychain "${RUNNER_TEMP}/dev.keychain"
}

sign_binary () {
  # TODO(REC-55): write this
  return
}

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
    -- \
    "${TARGETS[@]}"

install_cert
trap EXIT uninstall_cert

# TODO(REC-55): sign and notarize binaries on macOS, Windows

for target in "${TARGETS[@]}"; do
  cp "$(bazel cquery --output=files "${target}")" _out/
done
