# Vulnerability: Fortiswitch Panel - Detect
**Classification:** LOGIN
**Source:** Nuclei Template (`fortiswitch-panel.yaml`)

## Description
Fortiswitch panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

