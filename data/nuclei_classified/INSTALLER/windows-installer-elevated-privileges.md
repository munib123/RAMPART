# Vulnerability: Windows Installer Elevated Privileges Enabled
**Classification:** INSTALLER
**Source:** Nuclei Template (`windows-installer-elevated-privileges.yaml`)

## Description
Checks if Windows Installer runs with elevated privileges for non-admin users, which could be exploited.

## Secure Mitigation
Disable elevated privileges for non-admin users in Windows Installer settings.

