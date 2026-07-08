# Vulnerability: Metabase Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`metabase-panel.yaml`)

## Description
Metabase login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

