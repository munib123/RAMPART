# Vulnerability: OSASI Login - Panel
**Classification:** OSASI
**Source:** Nuclei Template (`osasi-panel.yaml`)

## Description
OSASI Login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/users/login
```

