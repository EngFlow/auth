load("@rules_go//go:def.bzl", "go_binary", "go_cross_binary", "go_library", "go_test")
load("//infra:visibility.bzl", "RELEASE_ARTIFACT")

go_library(
    name = "engflow_auth_lib",
    srcs = [
        "config.go",
        "main.go",
    ],
    importpath = "github.com/EngFlow/auth/cmd/engflow_auth",
    visibility = ["//visibility:private"],
    deps = [
        "//internal/autherr",
        "//internal/browser",
        "//internal/buildstamp",
        "//internal/oauthdevice",
        "//internal/oauthtoken",
        "@com_github_engflow_credential_helper_go//:credential-helper-go",
        "@com_github_golang_jwt_jwt_v5//:jwt",
        "@com_github_urfave_cli_v2//:cli",
        "@org_golang_x_oauth2//:oauth2",
    ],
)

go_binary(
    name = "engflow_auth",
    embed = [":engflow_auth_lib"],
    visibility = ["//visibility:public"],
)

go_test(
    name = "engflow_auth_test",
    srcs = ["main_test.go"],
    embed = [":engflow_auth_lib"],
    deps = [
        "//internal/autherr",
        "//internal/browser",
        "//internal/oauthdevice",
        "//internal/oauthtoken",
        "@com_github_golang_jwt_jwt_v5//:jwt",
        "@com_github_stretchr_testify//assert",
        "@org_golang_x_oauth2//:oauth2",
    ],
)

go_cross_binary(
    name = "engflow_auth_macos_arm64",
    platform = "@rules_go//go/toolchain:darwin_arm64_cgo",
    target = ":engflow_auth",
    visibility = RELEASE_ARTIFACT,
)

go_cross_binary(
    name = "engflow_auth_windows_x64",
    platform = "@rules_go//go/toolchain:windows_amd64_cgo",
    target = ":engflow_auth",
    visibility = RELEASE_ARTIFACT,
)

go_cross_binary(
    name = "engflow_auth_linux_x64",
    platform = "@rules_go//go/toolchain:linux_amd64_cgo",
    target = ":engflow_auth",
    visibility = RELEASE_ARTIFACT,
)
