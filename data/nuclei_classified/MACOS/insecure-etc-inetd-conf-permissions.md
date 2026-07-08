# Vulnerability: macOS Insecure /etc/inetd.conf Permissions
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-etc-inetd-conf-permissions.yaml`)

## Description
Verifies permissions on the /etc/inetd.conf file used to configure the inetd daemon on macOS.

## Secure Mitigation
Ensure that the /etc/inetd.conf file is owned by root with a system group (wheel, admin, etc.) and has permissions of 0644 or more restrictive.

