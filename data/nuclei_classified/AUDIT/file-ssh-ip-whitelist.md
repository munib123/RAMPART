# Vulnerability: Unrestricted SSH Access from Non-Whitelisted IPs
**Classification:** AUDIT
**Source:** Nuclei Template (`file-ssh-ip-whitelist.yaml`)

## Description
SSH access is not restricted to specific IP addresses, allowing connections from any source. This increases the risk of unauthorized access and brute-force attacks.

## Secure Mitigation
Restrict SSH to specific IPs in /etc/ssh/sshd_config by setting ListenAddress <trusted-IP> and restarting the SSH service.

