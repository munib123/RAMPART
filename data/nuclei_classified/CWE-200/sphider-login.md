# Vulnerability: Sphider Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sphider-login.yaml`)

## Description
Sphider admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/spider.php
GET {{BaseURL}}/sphider/admin/admin.php
GET {{BaseURL}}/search/admin/admin.php
```

