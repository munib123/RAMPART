# Vulnerability: macOS Insecure /etc/exports Permissions
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-etc-exports-permissions.yaml`)

## Description
Identifies insecure permissions on the /etc/exports file used to configure NFS exports on macOS.

## Secure Mitigation
Ensure that the /etc/exports file is owned by root with a system group (wheel, admin, etc.) and has permissions of 0644 or more restrictive.

