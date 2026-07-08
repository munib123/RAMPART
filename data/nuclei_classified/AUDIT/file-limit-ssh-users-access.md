# Vulnerability: Limit SSH Users Access
**Classification:** AUDIT
**Source:** Nuclei Template (`file-limit-ssh-users-access.yaml`)

## Description
Restricting SSH user access improves security by allowing only authorized users to connect, reducing the risk of unauthorized logins and potential attacks.

## Secure Mitigation
Restrict SSH access by configuring AllowUsers or AllowGroups in /etc/ssh/sshd_config and restart the SSH service.

