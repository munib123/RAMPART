# Vulnerability: Ensure SSH HostbasedAuthentication - Disabled
**Classification:** CIS
**Source:** Nuclei Template (`ssh-hostbasedauth-disabled.yaml`)

## Description
The HostbasedAuthentication parameter determines whether SSH authentication is permitted using trusted hosts, based on entries in .rhosts or /etc/hosts.equiv, in combination with successful public key authentication from the client host.

## Secure Mitigation
Edit /etc/ssh/sshd_config to set 'HostbasedAuthentication no' and restart SSH service with 'sudo systemctl restart sshd'.

