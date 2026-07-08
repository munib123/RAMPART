# Vulnerability: Safe Search Replace Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`searchreplacedb2-exposure.yaml`)

## Description
Safe Search Replace is exposed leaking internal info.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/searchreplacedb2.php
```

