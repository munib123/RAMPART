# Vulnerability: XXLJOB Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xxljob-panel.yaml`)

## Description
XXLJOB admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xxl-job-admin/toLogin
GET {{BaseURL}}/toLogin
```

