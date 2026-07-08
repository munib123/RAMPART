# Vulnerability: Generic Linux - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`generic-linux-lfi.yaml`)

## Description
Generic Linux is subject to Local File Inclusion - the vulnerability was identified by requesting /etc/passwd from the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

