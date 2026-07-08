# Vulnerability: Event Debug Server Status
**Classification:** EVENT
**Source:** Nuclei Template (`event-debug-server-status.yaml`)

## Description
Exposes server status,logs and internal information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

