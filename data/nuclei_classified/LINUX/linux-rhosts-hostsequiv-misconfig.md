# Vulnerability: Rhosts and Hosts.equiv Misconfiguration Check
**Classification:** LINUX
**Source:** Nuclei Template (`linux-rhosts-hostsequiv-misconfig.yaml`)

## Description
Assessed the presence and configuration of .rhosts and /etc/hosts.equiv files. Files with unsafe '+' entries, incorrect permissions, or improper ownership could have permitted unauthorized remote command execution via rlogin or rsh.

