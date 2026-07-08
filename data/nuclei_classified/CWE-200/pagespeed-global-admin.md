# Vulnerability: Pagespeed Global Admin - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pagespeed-global-admin.yaml`)

## Description
Pagespeed Global Admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pagespeed-global-admin/
```

