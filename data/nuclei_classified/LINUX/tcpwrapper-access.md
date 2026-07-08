# Vulnerability: TCP Wrapper Access Control Check
**Classification:** LINUX
**Source:** Nuclei Template (`tcpwrapper-access.yaml`)

## Description
Checked if IP and port restrictions were properly applied using TCP Wrapper (/etc/hosts.allow and /etc/hosts.deny). Reported systems as vulnerable if unrestricted remote access (e.g. Telnet, RSH, SSH) was possible.

