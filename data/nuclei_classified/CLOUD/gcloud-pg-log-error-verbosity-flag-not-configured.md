# Vulnerability: Log Error Verbosity Flag Not Configured Properly for PostgreSQL Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-error-verbosity-flag-not-configured.yaml`)

## Description
Ensure that the "log_error_verbosity" database flag configured for your Google Cloud PostgreSQL database instances is set to DEFAULT or to a stricter value. The "log_error_verbosity" flag determines the level of detail recorded in the server log for logged messages. Valid values are TERSE, DEFAULT, and VERBOSE, with TERSE being the most restrictive and VERBOSE providing the most detail.

## Secure Mitigation
Set the "log_error_verbosity" flag to DEFAULT or a stricter value (e.g., TERSE) to balance logging detail and performance, as per your organization's logging policy.

