# Vulnerability: Cisco ServiceGrid Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-servicegrid.yaml`)

## Description
Cisco ServiceGrid login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pages/sdcall/Login.jsp
```

