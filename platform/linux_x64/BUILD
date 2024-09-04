load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")
load(":cc_toolchain_config.bzl", "cc_toolchain_config")

package(default_visibility = ["//visibility:public"])

platform(
    name = "linux_x64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
        "@bazel_tools//tools/cpp:clang",
        "@rules_go//go/toolchain:cgo_on",
    ],
    exec_properties = {
        "container-image": "docker://645088952840.dkr.ecr.eu-west-1.amazonaws.com/engflow-re/debian12-x64@sha256:b636ba1e2fd5da78372596e9e882a6a19e8931b52a7ec37e17587d84f1fb8e76",
        "Pool": "linux_x64",
    },
)

toolchain(
    name = "cc-toolchain",
    exec_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    toolchain = ":cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

cc_toolchain_suite(
    name = "toolchain",
    tags = ["manual"],
    toolchains = {
        "k8|gcc": ":cc-compiler-k8",
        "k8": ":cc-compiler-k8",
    },
)

cc_toolchain(
    name = "cc-compiler-k8",
    all_files = ":linux_gnu_x86",
    ar_files = ":linux_gnu_x86",
    as_files = ":linux_gnu_x86",
    compiler_files = ":linux_gnu_x86",
    dwp_files = ":linux_gnu_x86",
    linker_files = ":linux_gnu_x86",
    module_map = None,
    objcopy_files = ":linux_gnu_x86",
    strip_files = ":linux_gnu_x86y",
    supports_param_files = 1,
    toolchain_config = ":linux_gnu_x86",
    toolchain_identifier = "linux_gnu_x86",
)

cc_toolchain_config(
    name = "linux_gnu_x86",
    abi_libc_version = "glibc_2.19",
    abi_version = "gcc",
    compile_flags = [
        "-fstack-protector",
        "-Wall",
        "-Wunused-but-set-parameter",
        "-Wno-free-nonheap-object",
        "-fno-omit-frame-pointer",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "k8",
    cxx_builtin_include_directories = [
        "/usr/lib/gcc/x86_64-linux-gnu/10/include",
        "/usr/local/include",
        "/usr/include/x86_64-linux-gnu",
        "/usr/include",
        "/usr/include/c++/10",
        "/usr/include/x86_64-linux-gnu/c++/10",
        "/usr/include/c++/10/backward",
    ],
    cxx_flags = ["-std=c++14"],
    dbg_compile_flags = ["-g"],
    host_system_name = "i686-unknown-linux-gnu",
    link_flags = [
        "-fuse-ld=gold",
        "-Wl,-no-as-needed",
        "-Wl,-z,relro,-z,now",
        "-B/usr/bin",
        "-pass-exit-codes",
    ],
    link_libs = [
        "-lstdc++",
        "-lm",
    ],
    opt_compile_flags = [
        "-g0",
        "-O2",
        "-D_FORTIFY_SOURCE=1",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = ["-Wl,--gc-sections"],
    supports_start_end_lib = True,
    target_libc = "glibc_2.19",
    target_system_name = "x86_64-unknown-linux-gnu",
    tool_paths = {
        "ar": "/usr/bin/ar",
        "ld": "/usr/bin/ld",
        "llvm-cov": "None",
        "llvm-profdata": "None",
        "cpp": "/usr/bin/cpp",
        "gcc": "/usr/bin/gcc",
        "dwp": "/usr/bin/dwp",
        "gcov": "/usr/bin/gcov",
        "nm": "/usr/bin/nm",
        "objcopy": "/usr/bin/objcopy",
        "objdump": "/usr/bin/objdump",
        "strip": "/usr/bin/strip",
    },
    toolchain_identifier = "linux_gnu_x86",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

filegroup(
    name = "compiler_deps",
    srcs = glob(
        ["extra_tools/**"],
        allow_empty = True,
    ) + [":builtin_include_directory_paths"],
)

filegroup(
    name = "empty",
)
