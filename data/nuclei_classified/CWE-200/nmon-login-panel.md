# Vulnerability: nMon Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nmon-login-panel.yaml`)

## Description
nMon login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?route=signin
```

