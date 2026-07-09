# Nuclei Template: Windows - Local File Inclusion
**Template ID:** generic-windows-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`generic-windows-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Windows is vulnerable to local file inclusion because of searches for /windows/win.ini on passed URLs.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

