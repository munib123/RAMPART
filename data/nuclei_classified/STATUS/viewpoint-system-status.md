# Vulnerability: ViewPoint System Status
**Classification:** STATUS
**Source:** Nuclei Template (`viewpoint-system-status.yaml`)

## Description
ViewPoint System status page is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

