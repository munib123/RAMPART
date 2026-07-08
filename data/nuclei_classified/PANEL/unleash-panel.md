# Vulnerability: Unleash Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`unleash-panel.yaml`)

## Description
Open-source feature management solution built for developers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
GET {{BaseURL}}/sign-in
GET {{BaseURL}}/favicon.ico
```

