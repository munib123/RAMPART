# Vulnerability: LibreChat Login Panel - Detection
**Classification:** PANEL
**Source:** Nuclei Template (`librechat-login-panel.yaml`)

## Description
Detected LibreChat login panel. LibreChat is an open-source, self-hosted AI chat interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

