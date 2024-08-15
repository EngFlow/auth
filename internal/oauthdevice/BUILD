load("@rules_go//go:def.bzl", "go_library")

go_library(
    name = "oauthdevice",
    srcs = [
        "authenticator.go",
        "logging.go",
    ],
    importpath = "github.com/EngFlow/auth/internal/oauthdevice",
    visibility = ["//:__subpackages__"],
    deps = [
        "@com_github_davecgh_go_spew//spew",
        "@org_golang_x_oauth2//:oauth2",
    ],
)
