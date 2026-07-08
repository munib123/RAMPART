# Vulnerability: Lazy File Manager
**Classification:** EXPOSURE
**Source:** Nuclei Template (`lazy-file.yaml`)

## Description
lfm.php file in exposed in Lazy File Manager.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lfm.php
```

