# Vulnerability: macOS Insecure /etc/sudoers Permissions
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-sudoers-permissions.yaml`)

## Description
Audits permissions on the /etc/sudoers file that defines which users can run commands with root privileges on macOS.

## Secure Mitigation
Ensure that the /etc/sudoers file is owned by root with a system group (wheel, admin, etc.) and has permissions of 0440 or more restrictive.

