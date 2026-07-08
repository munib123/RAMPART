# Vulnerability: macOS SSH Service Running
**Classification:** MACOS
**Source:** Nuclei Template (`ssh-service-running.yaml`)

## Description
Checks if the SSH service (Remote Login) is running on the macOS system.

## Secure Mitigation
Disable the SSH service if it is not needed. If it is required, ensure that it is properly configured with strong passwords and key-based authentication.

