# engflow_auth

This repository provides `engflow_auth`, a [Bazel credential helper](https://blog.engflow.com/2023/10/20/secure-builds-with-credential-helpers/) that helps you automatically obtain and securely store EngFlow authentication tokens.

## Installation

### One-time setup

1. Download the appropriate binary from the latest [release
   page](https://github.com/EngFlow/auth/releases/latest)
1. Copy the downloaded binary to a directory on the system `$PATH` and mark as
   executable (if necessary)
1. Configure `.bazelrc`: In the `.bazelrc` file of either your project or user,
   add a `build` flag that sets `--credential_helper` for your cluster. For
   instance:

   ```
   build:engflow --credential_helper=example.cluster.engflow.com=/path/to/engflow_auth
   ```

   would configure the credential helper correctly when `--config=engflow` is
   passed to a bazel invocation. See [Bazel's config
   documentation](https://bazel.build/run/bazelrc) for more info on bazelrc
   files, and [EngFlow setup
   documentation](https://docs.engflow.com/re/client/bazel-first-time.html#4-set-up-bazelrc)
   for EngFlow-specific setup and tips.

### Use

Each day, run `engflow_auth login [CLUSTER URL]` to obtain an auth credential;
the application will emit a URL to visit to complete the login process.

## Reporting Issues

To report security vulnerabilities on `engflow_auth`, please send an email to
security@engflow.com containing:

* impact of the bug/vulnerability
* steps to reproduce the issue
* summary of expected vs. actual behavior observed

For usability bugs and feature requests, please contact us through your DSE or
via our [existing support
channels](https://docs.engflow.com/support/get-day-to-day-support.howto.html).

## Building

The CLI can be built via either the Go toolchain or Bazel; released binaries are
built via Bazel.

To build release binaries, run:

```
bazel build --config=release //:release_artifacts
```

## Contributing

We are not accepting pull requests from external contributors at this time due
to both legal and technical reasons.

The best way to report serious bugs/vulnerabilities is via email to
security@engflow.com (see above section);

If you are an EngFlow customer and would like feature additions or
quality-of-life fixes, please discuss these with your DSE to get them
appropriately prioritized.
