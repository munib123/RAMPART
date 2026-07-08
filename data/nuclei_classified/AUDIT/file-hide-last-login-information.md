# Vulnerability: Hide SSH Last Login Information
**Classification:** AUDIT
**Source:** Nuclei Template (`file-hide-last-login-information.yaml`)

## Description
SSH last login information helps detect unauthorized access but may expose user activity details to attackers.

## Secure Mitigation
Set PrintLastLog no in /etc/ssh/sshd_config to disable last login information and restart the SSH service.

