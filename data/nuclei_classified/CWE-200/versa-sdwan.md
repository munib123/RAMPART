# Vulnerability: Versa SD-WAN Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`versa-sdwan.yaml`)

## Description
Versa SD-WAN login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/versa/login.html
```

