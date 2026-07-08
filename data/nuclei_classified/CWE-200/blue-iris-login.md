# Vulnerability: Blue Iris Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blue-iris-login.yaml`)

## Description
Blue Iris login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.htm
```

