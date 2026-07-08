# Vulnerability: Disable SSH Protocol
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-ssh-protocol.yaml`)

## Description
Using SSH Protocol 1 is insecure as it lacks strong encryption and integrity checks, making it vulnerable to man-in-the-middle attacks, session hijacking, and other exploits. It is recommended to use SSH Protocol 2 for enhanced security.

## Secure Mitigation
Set Protocol 2 in /etc/ssh/sshd_config to disable SSH Protocol 1 and restart the SSH service.

