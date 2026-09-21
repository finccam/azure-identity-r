# azidentity 1.1.0

* Bound IMDS discovery to one second without retries so local authentication
  reaches Azure CLI promptly when managed identity is unavailable. Preserve
  normal authentication retries after IMDS responds and bypass the probe for
  configured managed-identity sources (#4).

# azidentity 1.0.0

* Initial CRAN submission.
