# Vulnerability: Umami Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`umami-panel.yaml`)

## Description
simple, fast, privacy-focused, open-source analytics solution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/~404
```

