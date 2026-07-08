# Vulnerability: Oracle Access Management Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`oracle-access-management.yaml`)

## Description
Oracle Access Management login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/oam/pages/login.jsp
GET {{BaseURL}}
```

