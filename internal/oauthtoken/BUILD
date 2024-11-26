load("@rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "oauthtoken",
    srcs = [
        "debug.go",
        "fake.go",
        "file.go",
        "keyring.go",
        "load_storer.go",
    ],
    importpath = "github.com/EngFlow/auth/internal/oauthtoken",
    visibility = ["//:__subpackages__"],
    deps = [
        "@com_github_golang_jwt_jwt_v5//:jwt",
        "@com_github_zalando_go_keyring//:go-keyring",
        "@org_golang_x_oauth2//:oauth2",
    ],
)

go_test(
    name = "oauthtoken_test",
    srcs = [
        "keyring_test.go",
        "load_storer_test.go",
    ],
    embed = [":oauthtoken"],
    deps = [
        "@com_github_google_uuid//:uuid",
        "@com_github_stretchr_testify//assert",
        "@com_github_stretchr_testify//require",
        "@com_github_zalando_go_keyring//:go-keyring",
        "@org_golang_x_oauth2//:oauth2",
    ],
)
