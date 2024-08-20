load("@rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "auth",
    srcs = ["authenticator.go"],
    importpath = "github.com/EngFlow/auth/internal/auth",
    visibility = ["//:__subpackages__"],
    deps = [
        "//internal/autherr",
        "//internal/browser",
        "//internal/buildstamp",
        "//internal/httputil",
        "@org_golang_x_oauth2//:oauth2",
    ],
)

go_test(
    name = "auth_test",
    srcs = ["authenticator_test.go"],
    embed = [":auth"],
    deps = [
        "@com_github_stretchr_testify//assert",
        "@com_github_stretchr_testify//mock",
        "@org_golang_x_oauth2//:oauth2",
    ],
)
