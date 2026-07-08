# Vulnerability: Overseerr Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`overseerr-panel.yaml`)

## Description
Overseerr is a request management and media discovery tool built to work with your existing Plex ecosystem.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

