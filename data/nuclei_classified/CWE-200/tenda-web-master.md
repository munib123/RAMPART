# Vulnerability: Tenda Web Master Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tenda-web-master.yaml`)

## Description
Tenda Web Master login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

