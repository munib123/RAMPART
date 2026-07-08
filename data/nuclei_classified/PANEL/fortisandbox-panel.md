# Vulnerability: Fortinet FortiSandbox Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`fortisandbox-panel.yaml`)

## Description
Fortinet FortiSandbox login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/fsa/login
GET {{BaseURL}}/ng/login?returnUrl=%2F
```

