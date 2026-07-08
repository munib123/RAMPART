# Vulnerability: Tautulli Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`tautulli-panel.yaml`)

## Description
A Python based monitoring and tracking tool for Plex Media Server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/auth/login
```

