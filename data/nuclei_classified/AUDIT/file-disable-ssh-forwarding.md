# Vulnerability: Disable SSH Forwarding
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-ssh-forwarding.yaml`)

## Description
SSH forwarding can enhance security by encrypting traffic (X11, agent, or port forwarding), but it also poses risks if misused. Attackers with access to a compromised system can pivot to other machines, potentially escalating privileges or stealing credentials.

## Secure Mitigation
Set X11Forwarding no and AllowTcpForwarding no in /etc/ssh/sshd_config to disable SSH forwarding and restart the SSH service.

