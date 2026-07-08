# Vulnerability: PocketBase Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`pocketbase-panel.yaml`)

## Description
PocketBase Login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_/#/login
```

