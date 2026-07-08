# Vulnerability: HPE OneView - Panel Detect
**Classification:** PANEL
**Source:** Nuclei Template (`hpe-oneview-panel.yaml`)

## Description
HPE OneView is an infrastructure management platform that provides automated management, monitoring, and updates for HPE servers, storage, and networking resources through a unified interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

