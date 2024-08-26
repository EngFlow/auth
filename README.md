# engflow_auth

This repository provides `engflow_auth`, a [Bazel credential helper](https://blog.engflow.com/2023/10/20/secure-builds-with-credential-helpers/) that helps you automatically obtain and securely store EngFlow authentication credentials.

## Installation

1. Download the appropriate binary from the latest [release
   page](https://github.com/EngFlow/auth/releases/latest).
1. Copy the downloaded binary to a directory on the system `$PATH` and mark as
   executable (if necessary).
1. In the `.bazelrc` file of either your project or user, add a line that sets `--credential_helper` for your cluster. For
   instance:

   ```
   build:engflow --credential_helper=example.cluster.engflow.com=/path/to/engflow_auth
   ```

   would configure the credential helper correctly when `--config=engflow` is
   passed to a bazel invocation. See [Bazel's config
   documentation](https://bazel.build/run/bazelrc) for more info on bazelrc
   files, and [EngFlow setup
   documentation](https://docs.engflow.com/re/client/bazel-first-time.html#4-set-up-bazelrc)
   for EngFlow-specific setup instructions.

## Use

1. Run `engflow_auth login [CLUSTER URL]` to obtain a credential. This prints a URL to visit in your browser.
1. Visit the URL to complete the process, logging in if necessary. `engflow_auth` will download and store a credential in on your system's encrypted keyring.

This process needs to be repeated after the credential expires, typically every 90 days.

## Use in a non-interactive environment

You can use `engflow_auth` to authenticate when no web browser is available, for example, on a continuous integration and testing server.

1. You may wish to create a service account with your authentication provider, then log into your EngFlow cluster with that account. The credential created here will let Bazel authenticate as this account.
1. On a machine with a web browser, complete the login process as described above:

    ```
    engflow_auth login [CLUSTER URL]
    ```

1. Export the credential to a file using the command below:

    ```
    engflow_auth export [CLUSTER URL] >cred.json
    ```

1. Save this credential as a secret, accessible in the non-interactive environment. For example, if you're using GitHub Actions, you can save this as a GitHub secret, then grant access in workflows that need it.
1. At the beginning of a job, retrieve the secret and import it using the command below. The `-store=file` flag may be necessary to store the credential as an unencrypted file instead of your encrypted keyring. Non-interactive environments typically don't have an encrypted keyring.

    ```
    engflow_auth import -store=file <cred.json
    ```

1. At the end of a job, remove the credential using the command below.

    ```
    engflow_auth logout [CLUSTER URL]
    ```

## Build from source

To build `engflow_auth` with Bazel, clone this repository then run:

```
bazel build //cmd/engflow_auth
```

To build and install `engflow_auth` with Go:

```
go install github.com/EngFlow/auth/cmd/engflow_auth@latest
```

To build release artifacts:

```
bazel build --config=release //:release_artifacts
```

## Reporting Issues

To report security vulnerabilities on `engflow_auth`, please send an email to
security@engflow.com containing:

* impact of the bug/vulnerability
* steps to reproduce the issue
* summary of expected vs. actual behavior observed

For usability bugs and feature requests, please contact us through your DSE or
via our [existing support
channels](https://docs.engflow.com/support/get-day-to-day-support.howto.html).

## Contributing

We are not accepting pull requests from external contributors at this time due
to both legal and technical reasons.

The best way to report serious bugs/vulnerabilities is via email to
security@engflow.com (see above section);

If you are an EngFlow customer and would like feature additions or
quality-of-life fixes, please discuss these with your DSE to get them
appropriately prioritized.
