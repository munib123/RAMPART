# Vulnerability: AstrBot WebUI Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`astrbot-panel-detect.yaml`)

## Description
Astrbot WebUI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

