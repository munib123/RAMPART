# Vulnerability: MSPControl Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mspcontrol-login.yaml`)

## Description
MSPControl login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Default.aspx?pid=Login
```

