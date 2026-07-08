# Vulnerability: WinRM Basic Authentication Enabled
**Classification:** WINDOWS
**Source:** Nuclei Template (`winrm-basic-auth-enabled.yaml`)

## Description
Verifies if Windows Remote Management (WinRM) allows basic (unencrypted) authentication.

## Secure Mitigation
Disable Basic authentication and configure secure authentication mechanisms like Kerberos or certificate-based authentication.

