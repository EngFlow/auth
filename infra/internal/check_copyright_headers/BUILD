load("@rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "check_copyright_headers_lib",
    srcs = ["main.go"],
    importpath = "github.com/EngFlow/auth/infra/internal/check_copyright_headers",
    visibility = ["//infra:__subpackages__"],
)

go_binary(
    name = "check_copyright_headers",
    embed = [":check_copyright_headers_lib"],
    visibility = ["//infra:__subpackages__"],
)
