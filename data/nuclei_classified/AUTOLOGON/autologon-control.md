# Vulnerability: Autologon Function Control Check
**Classification:** AUTOLOGON
**Source:** Nuclei Template (`autologon-control.yaml`)

## Description
Ensure the Autologon feature is disabled by verifying that the AutoAdminLogon registry value under
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon is either missing or set to "0".
A value of "1" indicates that login credentials may be stored in the registry, creating a potential security risk.

## Secure Mitigation
Disable Autologon by setting the AutoAdminLogon registry value to "0". This can be done using:
- Registry Editor: Go to HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon and set AutoAdminLogon to "0".

