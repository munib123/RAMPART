# Vulnerability: Prestashop Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`prestashop-admin-panel.yaml`)

## Description
Prestashop admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{paths}}/
```

