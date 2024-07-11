load("@gazelle//:def.bzl", "gazelle")
# gazelle:prefix github.com/EngFlow/auth

gazelle(name = "gazelle")

filegroup(
    name = "release_artifacts",
    srcs = [
        "//cmd/engflow_auth:engflow_auth_linux_x64",
        "//cmd/engflow_auth:engflow_auth_macos_arm64",
        "//cmd/engflow_auth:engflow_auth_windows_x64",
    ],
)
