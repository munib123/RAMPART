# Vulnerability: Ghost Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ghost-panel.yaml`)

## Description
Beautiful, modern publishing with email newsletters and paid subscriptions built-in.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ghost/#/signin
```

