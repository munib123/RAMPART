# Vulnerability: Change SSH Default Port
**Classification:** AUDIT
**Source:** Nuclei Template (`file-change-default-port.yaml`)

## Description
Reduces Automated Attacks: Changing the default port can help avoid most automated attacks that target port 22.

## Secure Mitigation
Set Port 2222 in /etc/ssh/sshd_config to change the default SSH port and restart the SSH service.

