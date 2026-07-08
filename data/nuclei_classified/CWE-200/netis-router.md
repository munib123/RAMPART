# Vulnerability: Netis Router Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netis-router.yaml`)

## Description
Netis router login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.htm
```

