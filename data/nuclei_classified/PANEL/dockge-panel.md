# Vulnerability: Dockge Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`dockge-panel.yaml`)

## Description
A fancy, easy-to-use and reactive self-hosted docker compose.yaml stack-oriented manager

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

