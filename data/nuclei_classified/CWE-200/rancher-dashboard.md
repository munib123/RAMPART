# Vulnerability: Rancher Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rancher-dashboard.yaml`)

## Description
Rancher Dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/dashboard/auth/login
```

