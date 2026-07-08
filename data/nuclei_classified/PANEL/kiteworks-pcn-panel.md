# Vulnerability: Kiteworks PCN Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`kiteworks-pcn-panel.yaml`)

## Description
Kiteworks PCN Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/locales/login_en.json
```

