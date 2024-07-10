load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

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
    visibility = ["//third_party/engflow_auth:__subpackages__"],
    deps = [
        "//third_party/engflow_auth/internal/autherr",
        "//third_party/go/github.com/golang-jwt/jwt/v5:jwt",
        "//third_party/go/github.com/zalando/go-keyring",
        "//third_party/go/golang.org/x/oauth2",
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
        "//third_party/engflow_auth/internal/autherr",
        "//third_party/go/github.com/golang-jwt/jwt/v5:jwt",
        "//third_party/go/github.com/google/uuid",
        "//third_party/go/github.com/stretchr/testify/assert",
        "//third_party/go/github.com/stretchr/testify/require",
        "//third_party/go/github.com/zalando/go-keyring",
        "//third_party/go/golang.org/x/oauth2",
    ],
)
