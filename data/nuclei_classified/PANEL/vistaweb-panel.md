# Vulnerability: Vista Web Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`vistaweb-panel.yaml`)

## Description
Vista Web login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/account/login
```

