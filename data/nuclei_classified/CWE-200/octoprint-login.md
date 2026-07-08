# Vulnerability: OctoPrint Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`octoprint-login.yaml`)

## Description
OctoPrint login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login/
```

