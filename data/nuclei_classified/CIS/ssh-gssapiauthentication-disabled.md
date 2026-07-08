# Vulnerability: sshd GSSAPIAuthentication - Disabled
**Classification:** CIS
**Source:** Nuclei Template (`ssh-gssapiauthentication-disabled.yaml`)

## Description
The GSSAPIAuthentication parameter in the SSH configuration file (sshd_config) controls whether GSSAPI-based user authentication is permitted. When enabled, it allows the use of Kerberos or other GSSAPI mechanisms for authenticating SSH connections.

## Secure Mitigation
Disable GSSAPIAuthentication by editing /etc/ssh/sshd_config to set GSSAPIAuthentication no and restart SSH with sudo systemctl restart sshd.

