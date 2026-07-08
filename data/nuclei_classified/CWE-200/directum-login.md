# Vulnerability: Directum Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`directum-login.yaml`)

## Description
Directum login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.aspx
```

