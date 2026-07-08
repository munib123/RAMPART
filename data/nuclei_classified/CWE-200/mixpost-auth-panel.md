# Vulnerability: Mixpost Auth Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mixpost-auth-panel.yaml`)

## Description
Mixpost authentication interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mixpost/login
```

