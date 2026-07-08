# Vulnerability: OCS Inventory Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ocs-inventory-login.yaml`)

## Description
OCS Inventory login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ocsreports
```

