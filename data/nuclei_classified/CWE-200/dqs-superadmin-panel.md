# Vulnerability: DQS Superadmin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dqs-superadmin-panel.yaml`)

## Description
DQS Superadmin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

