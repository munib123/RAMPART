# Vulnerability: macOS Insecure /etc/fstab Permissions
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-etc-fstab-permissions.yaml`)

## Description
Validates permissions on the /etc/fstab file that defines how disk partitions and filesystems are mounted on macOS.

## Secure Mitigation
Ensure that the /etc/fstab file is owned by root with a system group (wheel, admin, etc.) and has permissions of 0644 or more restrictive.

