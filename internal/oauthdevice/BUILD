load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "oauthdevice",
    srcs = ["authenticator.go"],
    importpath = "github.com/EngFlow/auth/internal/oauthdevice",
    visibility = ["//third_party/engflow_auth:__subpackages__"],
    deps = ["//third_party/go/golang.org/x/oauth2"],
)
