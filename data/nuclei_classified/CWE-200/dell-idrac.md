# Vulnerability: Dell IDRAC Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dell-idrac.yaml`)

## Description
Dell IDRAC panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/restgui/start.html
GET {{BaseURL}}/login.html
```

