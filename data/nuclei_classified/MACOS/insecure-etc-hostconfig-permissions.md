# Vulnerability: macOS Insecure /etc/hostconfig Permissions
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-etc-hostconfig-permissions.yaml`)

## Description
Evaluates permissions on the /etc/hostconfig file used to configure system services on macOS.

## Secure Mitigation
Ensure that the /etc/hostconfig file is owned by root with a system group (wheel, admin, etc.) and has permissions of 0644 or more restrictive.

