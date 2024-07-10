load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_cross_binary", "go_library", "go_test")

go_library(
    name = "engflow_auth_lib",
    srcs = ["main.go"],
    importpath = "github.com/EngFlow/auth/cmd/engflow_auth",
    visibility = ["//visibility:private"],
    deps = [
        "//third_party/engflow-credential-helper-go:credential-helper-go",
        "//third_party/engflow_auth/internal/autherr",
        "//third_party/engflow_auth/internal/browser",
        "//third_party/engflow_auth/internal/buildstamp",
        "//third_party/engflow_auth/internal/oauthdevice",
        "//third_party/engflow_auth/internal/oauthtoken",
        "//third_party/go/golang.org/x/oauth2",
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
        "//third_party/engflow_auth/internal/autherr",
        "//third_party/engflow_auth/internal/browser",
        "//third_party/engflow_auth/internal/oauthdevice",
        "//third_party/engflow_auth/internal/oauthtoken",
        "//third_party/go/github.com/stretchr/testify/assert",
        "//third_party/go/golang.org/x/oauth2",
    ],
)

go_cross_binary(
    name = "engflow_auth_macos_arm64",
    platform = "@io_bazel_rules_go//go/toolchain:darwin_arm64_cgo",
    target = ":engflow_auth",
)

go_cross_binary(
    name = "engflow_auth_windows_x64",
    platform = "@io_bazel_rules_go//go/toolchain:windows_amd64_cgo",
    target = ":engflow_auth",
)

go_cross_binary(
    name = "engflow_auth_linux_x64",
    platform = "@io_bazel_rules_go//go/toolchain:linux_amd64_cgo",
    target = ":engflow_auth",
)
