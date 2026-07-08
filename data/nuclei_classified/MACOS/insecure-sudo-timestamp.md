# Vulnerability: macOS Excessive Sudo Timestamp Timeout
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-sudo-timestamp.yaml`)

## Description
Checks if the sudo timestamp timeout is configured to an excessively long duration (100+ minutes).

## Secure Mitigation
Set the sudo timestamp to a reasonable value to reduce the risk of unauthorized access.

