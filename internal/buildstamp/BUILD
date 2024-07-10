load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "buildstamp",
    srcs = ["buildstamp.go"],
    importpath = "github.com/EngFlow/auth/internal/buildstamp",
    visibility = ["//third_party/engflow_auth:__subpackages__"],
    x_defs = {
        # These vars are populated by `infra/get_workspace_status` and are set
        # when the `--stamp` flag is passed to bazel. See
        # https://bazel.build/docs/user-manual#workspace-status for more info.
        "gitBranch": "{BUILD_SCM_BRANCH}",
        "gitSha": "{BUILD_SCM_REVISION}",
        "gitSourceTreeStatus": "{BUILD_SCM_STATUS}",
        "buildTimestamp": "{BUILD_TIMESTAMP}",
    },
)
