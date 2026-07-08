# Vulnerability: Amatera Stealer C2 Panel - Detect
**Classification:** C2
**Source:** Nuclei Template (`amatera-stealer-panel.yaml`)

## Description
Amatera Stealer C2 Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sign-in
```

