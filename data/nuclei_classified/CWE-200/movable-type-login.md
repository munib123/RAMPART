# Vulnerability: Movable Type Pro Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`movable-type-login.yaml`)

## Description
Movable Type Pro login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mt/admin
GET {{BaseURL}}/mt.cgi
```

