# Vulnerability: Unencrypted Passwords to SMB Servers Allowed
**Classification:** SMB
**Source:** Nuclei Template (`smb-allow-unencrypted-passwords.yaml`)

## Description
Verifies if the system allows sending unencrypted passwords to third-party SMB servers, which is a security risk.

## Secure Mitigation
Configure SMB to prevent sending unencrypted passwords.

