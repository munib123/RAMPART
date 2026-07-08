# Vulnerability: macOS Permissive Umask Configuration
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-umask.yaml`)

## Description
Verifies if the umask is configured with overly permissive values that create insecurely accessible files.

## Secure Mitigation
Set the umask to a more restrictive value to ensure that new files are created with secure permissions.

