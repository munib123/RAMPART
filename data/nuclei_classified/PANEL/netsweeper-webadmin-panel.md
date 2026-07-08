# Vulnerability: Netsweeper WebAdmin - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`netsweeper-webadmin-panel.yaml`)

## Description
Netsweeper is an internet content filtering and web policy management platform used by ISPs, governments, educational institutions, and enterprises to enforce acceptable use policies and restrict access to harmful content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

