# Vulnerability: Wagtail Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wagtail-cms-detect.yaml`)

## Description
The Wagtail panel has been detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/?next=/
GET {{BaseURL}}/admin/login/?next=/admin/
```

