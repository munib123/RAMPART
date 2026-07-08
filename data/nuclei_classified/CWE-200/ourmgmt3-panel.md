# Vulnerability: OurMGMT3 Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ourmgmt3-panel.yaml`)

## Description
OurMGMT3 admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin/login
```

