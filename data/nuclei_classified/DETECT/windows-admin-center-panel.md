# Vulnerability: Windows Admin Center Panel - Detection
**Classification:** DETECT
**Source:** Nuclei Template (`windows-admin-center-panel.yaml`)

## Description
Detect Windows Admin Center Panel web interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

