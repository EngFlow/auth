load("@rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "oauthtoken",
    srcs = [
        "cache_alert.go",
        "debug.go",
        "file.go",
        "keyring.go",
        "load_storer.go",
    ],
    importpath = "github.com/EngFlow/auth/internal/oauthtoken",
    visibility = ["//:__subpackages__"],
    deps = [
        "//internal/autherr",
        "@com_github_golang_jwt_jwt_v5//:go_default_library",
        "@com_github_zalando_go_keyring//:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
    ],
)

go_test(
    name = "oauthtoken_test",
    srcs = [
        "cache_alert_test.go",
        "file_test.go",
        "keyring_test.go",
    ],
    embed = [":oauthtoken"],
    deps = [
        "//internal/autherr",
        "@com_github_golang_jwt_jwt_v5//:go_default_library",
        "@com_github_google_uuid//:go_default_library",
        "@com_github_stretchr_testify//assert:go_default_library",
        "@com_github_stretchr_testify//require:go_default_library",
        "@com_github_zalando_go_keyring//:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
    ],
)
