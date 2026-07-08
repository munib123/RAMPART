# Vulnerability: Grandstream GRP Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`grandstream-grp-panel.yaml`)

## Description
Detected the presence of a Grandstream GRP web management login panel. The React-based SPA loads characteristic JavaScript modules including tl.account.ucm.js and webpack chunks for UCM modules.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

