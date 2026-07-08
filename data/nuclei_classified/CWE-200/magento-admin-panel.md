# Vulnerability: Magento Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`magento-admin-panel.yaml`)

## Description
Magento admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
```

