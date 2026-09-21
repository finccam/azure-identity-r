# azidentity

`azidentity` acquires Microsoft Azure OAuth 2.0 access tokens from R using
the Azure SDK for Rust.

## Installation

Using rpx:

```sh
rpx add azidentity
```

Using base R:

```r
install.packages("azidentity")
```

## GitHub releases

Pushing a tag matching the version in `DESCRIPTION` (for example, `v1.0.0`)
builds a source package and binaries for the current and previous R release
series (`release` and `oldrel-1`):

- Ubuntu 24.04, x86_64
- Windows, x86_64
- macOS, arm64 and x86_64

The [GitHub Release](https://github.com/finccam/azure-identity-r/releases)
includes a download table and `SHA256SUMS`. The source archive is named
`azidentity_<version>.tar.gz`. Binary containers are named by the matrix, for
example `binary-windows-x86_64-release.zip`. Each contains the standard R
package archive: `azidentity_<version>.zip` on Windows, `.tgz` on macOS, or
`.tar.gz` on Ubuntu. Choose a container matching your R release series and
platform, then extract the outer ZIP. Ubuntu binaries are built for Ubuntu
24.04.

Install a downloaded archive from a terminal with:

```sh
R CMD INSTALL <downloaded-package-archive>
```

The workflow builds the source archive once and compiles every binary from it.
It does not run a test suite or `R CMD check`.

## Usage

```r
library(azidentity)

token <- default_azure_credential(
  "https://management.azure.com/.default"
)
```

Treat the returned bearer token as a secret. Do not print it, log it, or
store it in source control.

## Credential Chain

The package attempts credentials in this order:

1. Environment credential
2. Workload identity credential
3. Managed identity credential
4. Azure CLI credential
5. Azure Developer CLI credential

Environment authentication uses `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
`AZURE_CLIENT_SECRET`. For managed identity, a non-empty `AZURE_CLIENT_ID`
selects a user-assigned identity; otherwise, the system-assigned identity is
used.

The first successful credential is reused for the lifetime of the R process.
Tokens are cached by scope and refreshed when fewer than five minutes remain
before expiration.

## Requirements

Installing from source requires Cargo, Rust 1.88 or newer, and `xz`.

This is an independent project that uses the Microsoft Azure SDK for Rust. It
is not affiliated with or endorsed by Microsoft.
