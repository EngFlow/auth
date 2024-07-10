load("@rules_go//go:def.bzl", "go_library")

go_library(
    name = "oauthdevice",
    srcs = ["authenticator.go"],
    importpath = "github.com/EngFlow/auth/internal/oauthdevice",
    visibility = ["//:__subpackages__"],
    deps = ["@org_golang_x_oauth2//:go_default_library"],
)
