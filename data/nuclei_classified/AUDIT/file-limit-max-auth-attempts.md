# Vulnerability: Limit Maximum SSH Authentication Attempts
**Classification:** AUDIT
**Source:** Nuclei Template (`file-limit-max-auth-attempts.yaml`)

## Description
Limiting maximum SSH authentication attempts reduces the risk of brute-force attacks by restricting failed login attempts, enhancing security against unauthorized access

## Secure Mitigation
Set MaxAuthTries 3 in /etc/ssh/sshd_config to limit SSH authentication attempts and restart the SSH service.

