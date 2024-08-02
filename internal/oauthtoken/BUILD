load("@rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "oauthtoken",
    srcs = [
        "cache_alert.go",
        "debug.go",
        "fake.go",
        "keyring.go",
        "load_storer.go",
    ],
    importpath = "github.com/EngFlow/auth/internal/oauthtoken",
    visibility = ["//:__subpackages__"],
    deps = [
        "//internal/autherr",
        "@com_github_golang_jwt_jwt_v5//:jwt",
        "@com_github_zalando_go_keyring//:go-keyring",
        "@org_golang_x_oauth2//:oauth2",
    ],
)

go_test(
    name = "oauthtoken_test",
    srcs = [
        "cache_alert_test.go",
        "keyring_test.go",
    ],
    embed = [":oauthtoken"],
    deps = [
        "//internal/autherr",
        "@com_github_golang_jwt_jwt_v5//:jwt",
        "@com_github_google_uuid//:uuid",
        "@com_github_stretchr_testify//assert",
        "@com_github_stretchr_testify//require",
        "@com_github_zalando_go_keyring//:go-keyring",
        "@org_golang_x_oauth2//:oauth2",
    ],
)
