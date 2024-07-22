#!/usr/bin/env bash

set -o nounset -o pipefail -o errexit
[[ "${SCRIPT_DEBUG:-"off"}" == "on" ]] && set -o xtrace

if [[ "$#" -ne 1 ]]; then
  echo "Want 1 argument; got $# arguments"
  exit 1
fi

# Taken from https://semver.org/, with a `v` prepended
readonly SEMVER_REGEX='^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
readonly RELEASE_VERSION="$1"
readonly GH_CLI_URL='https://storage.googleapis.com/engflow-tools-public/github.com/cli/cli/releases/download/v2.52.0/gh_2.52.0_linux_amd64.tar.gz'
readonly GH_CLI_EXPECTED_SHA256='3ea6ed8b2585f406a064cecd7e1501e58f56c8e7ca764ae1f3483d1b8ed68826'

# Check that supplied version string follows semver
if ! grep --quiet --extended-regexp "${SEMVER_REGEX}" <<<${RELEASE_VERSION}; then
  echo "Supplied version string '${RELEASE_VERSION}' does not follow semver; exiting"
  exit 1
fi

function cleanup {
  rm -rf "${GH_CLI_DIR}"
}

# Download and verify Github CLI
# TODO(CUS-353): Remove this after installing Github CLI in the self-hosted
# environment (run via Docker?)
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

# Check that the current commit is on either `main` or a release branch
readonly EXPECTED_RELEASE_BRANCH="$(sed --regexp-extended 's|(v[0-9]+.[0-9]+).[0-9]+|release/\1|' <<<${RELEASE_VERSION})"
if ! git branch \
  --contains "$(git rev-parse HEAD)" \
  | grep --quiet --extended-regexp "main|${EXPECTED_RELEASE_BRANCH}"; then
    echo "Commit $(git rev-parse HEAD) is not on main or release branch ${EXPECTED_RELEASE_BRANCH}; exiting"
    exit 1
fi

# Build release artifacts
bazel build \
    --config=release \
    -- \
    //:release_artifacts

# Create release
${GH_CLI} release create \
    "v${RELEASE_VERSION}" \
    --generate-notes \
    "$(realpath bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_linux_x64)#engflow_auth (Linux, x64)" \
    "$(realpath bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_macos_arm64)#engflow_auth (macOS, arm64)" \
    "$(realpath bazel-out/k8-fastbuild-ST-*/bin/cmd/engflow_auth/engflow_auth_windows_x64)#engflow_auth (Windows, x64)"
