# Vulnerability: macOS World-Readable TTY Devices
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-tty-permissions.yaml`)

## Description
Checks if TTY devices are readable by all users, potentially allowing session snooping.

## Secure Mitigation
Ensure that TTYs are not readable by all users.

