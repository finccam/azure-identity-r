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
