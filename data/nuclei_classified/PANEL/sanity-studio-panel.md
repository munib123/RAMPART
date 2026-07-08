# Vulnerability: Sanity Studio Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`sanity-studio-panel.yaml`)

## Description
Sanity Studio panel was detected. Sanity is a headless CMS platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

