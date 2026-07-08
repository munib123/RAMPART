# Vulnerability: Disable SSH Empty Password
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-empty-password.yaml`)

## Description
Allowing empty passwords in SSH poses a severe security risk, enabling unauthorized access, brute-force attacks, and potential system compromise. It should always be disabled to prevent unauthorized logins.

## Secure Mitigation
Set PermitEmptyPasswords no in /etc/ssh/sshd_config to disable empty password logins and restart the SSH service.

