# Vulnerability: Immich Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`immich-panel.yaml`)

## Description
Immich is a self-hosted photo and video backup solution

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

