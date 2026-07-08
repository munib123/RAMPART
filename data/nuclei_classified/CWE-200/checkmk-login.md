# Vulnerability: Checkmk Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`checkmk-login.yaml`)

## Description
Checkmk login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

