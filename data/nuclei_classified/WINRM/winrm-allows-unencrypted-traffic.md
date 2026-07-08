# Vulnerability: WinRM Allows Unencrypted Traffic
**Classification:** WINRM
**Source:** Nuclei Template (`winrm-allows-unencrypted-traffic.yaml`)

## Description
Verifies if Windows Remote Management (WinRM) is allowing unencrypted traffic, exposing sensitive data.

## Secure Mitigation
Configure WinRM to require encrypted traffic by setting `AllowUnencrypted` to `False`.

