# Vulnerability: Trellix Login Panel
**Classification:** TRELLIX
**Source:** Nuclei Template (`trellix-panel.yaml`)

## Description
Trellix login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/login
```

