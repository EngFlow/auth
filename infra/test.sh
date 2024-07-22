#!/usr/bin/env bash

set -o nounset -o pipefail -o errexit
[[ "${SCRIPT_DEBUG:-"off"}" == "on" ]] && set -o xtrace

if [ -z "${OS-}" ]; then
  echo "OS must be set" >&2
  exit 1
fi
if [ -z "${ARCH-}" ]; then
  echo "ARCH must be set" >&2
  exit 1
fi

case "${OS}-${ARCH}" in
linux-x64)
  remote_config=remote_linux_x64
  ;;
macos-x64)
  remote_config=remote_macos_x64
  ;;
windows-x64)
  remote_config=remote_windows_x64
  ;;
*)
  echo "unknown OS / arch combo. OS must be one of linux, macos, windows. ARCH must be x64." >&2
  exit 1
esac

bazel_flags=(
  --config=noninteractive
  --config=opal
  --config="${remote_config}"
)

#`echo "Running Bazel tests..."
bazel build "${bazel_flags[@]}" //...

echo "Running Go tests..."
bazel run @rules_go//go -- test ./...
bazel run @rules_go//go -- clean -cache -modcache
