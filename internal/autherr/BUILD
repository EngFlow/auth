load("@rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "autherr",
    srcs = ["coded_error.go"],
    importpath = "github.com/EngFlow/auth/internal/autherr",
    visibility = ["//:__subpackages__"],
)

go_test(
    name = "autherr_test",
    srcs = ["coded_error_test.go"],
    embed = [":autherr"],
    deps = ["@com_github_urfave_cli_v2//:cli"],
)
