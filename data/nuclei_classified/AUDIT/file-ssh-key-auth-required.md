# Vulnerability: SSH Key-Based Authentication - Disabled
**Classification:** AUDIT
**Source:** Nuclei Template (`file-ssh-key-auth-required.yaml`)

## Description
SSH key-based authentication is disabled, allowing password-based logins, which increases the risk of brute-force attacks and unauthorized access.

## Secure Mitigation
Enable SSH key-based authentication by adding the public key to ~/.ssh/authorized_keys and disabling password authentication in /etc/ssh/sshd_config (PasswordAuthentication no).

