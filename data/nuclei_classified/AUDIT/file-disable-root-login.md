# Vulnerability: Disable SSH Root Login
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-root-login.yaml`)

## Description
Disabling direct root login can help prevent unauthorized users from gaining full control over your system.

## Secure Mitigation
Set PermitRootLogin no in /etc/ssh/sshd_config to disable root login and restart the SSH service.

