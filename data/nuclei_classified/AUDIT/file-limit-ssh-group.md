# Vulnerability: Limit SSH Users Group Access
**Classification:** AUDIT
**Source:** Nuclei Template (`file-limit-ssh-group.yaml`)

## Description
Limiting SSH user group access enhances security by restricting login permissions to authorized groups, reducing the attack surface and preventing unauthorized access.

## Secure Mitigation
Ensure only necessary users are listed in AllowUsers within /etc/ssh/sshd_config, then restart the SSH service.

