# Vulnerability: DbGate Web Client Management - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dbgate-panel.yaml`)

## Description
The DbGate Web Client Management Panel is detected on the target system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

