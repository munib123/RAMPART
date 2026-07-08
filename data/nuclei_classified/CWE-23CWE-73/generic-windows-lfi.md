# Vulnerability: Windows - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`generic-windows-lfi.yaml`)

## Description
Windows is vulnerable to local file inclusion because of searches for /windows/win.ini on passed URLs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

