# Vulnerability: SphinxOnline Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`sphinxonline-panel.yaml`)

## Description
SphinxOnline Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SphinxAuth/Account/Login
```

