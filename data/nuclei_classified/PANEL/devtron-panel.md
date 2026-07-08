# Vulnerability: Devtron Panel Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`devtron-panel.yaml`)

## Description
Devtron Panel login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard/login
```

