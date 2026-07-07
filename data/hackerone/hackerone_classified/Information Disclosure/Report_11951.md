# HackerOne Report: SSH Port Wide Open
**Report ID:** 11951
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
SSH port is wide open, this can give attackers additional information to coordinate an attack:

Nmap scan report for joola.io (178.79.174.108)
Host is up (0.033s latency).
rDNS record for 178.79.174.108: li311-108.members.linode.com
Not shown: 994 closed ports
PORT    STATE    SERVICE
20/tcp  filtered ftp-data
22/tcp  open     ssh
53/tcp  filtered domain
80/tcp  open     http
119/tcp filtered nntp
443/tcp open     https

## Discussion & Remediation Timeline
