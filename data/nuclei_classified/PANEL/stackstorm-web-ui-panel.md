# Vulnerability: StackStorm Web UI - Panel Detect
**Classification:** PANEL
**Source:** Nuclei Template (`stackstorm-web-ui-panel.yaml`)

## Description
StackStorm Web UI interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

