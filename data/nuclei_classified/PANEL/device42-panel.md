# Vulnerability: Device42 Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`device42-panel.yaml`)

## Description
Device42 was detected — a Discovery, Asset Management and Dependency Mapping for Data Center and Cloud.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login/?next=/
GET {{BaseURL}}
```

