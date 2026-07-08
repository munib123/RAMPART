# Vulnerability: Gogs Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gogs-panel.yaml`)

## Description
Gogs login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/login
```

