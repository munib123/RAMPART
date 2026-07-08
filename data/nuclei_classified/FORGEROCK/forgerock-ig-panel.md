# Vulnerability: ForgeRock IG Login/Welcome Page - Detect
**Classification:** FORGEROCK
**Source:** Nuclei Template (`forgerock-ig-panel.yaml`)

## Description
Detects ForgeRock Identity Gateway login or welcome page and extracts version number

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

