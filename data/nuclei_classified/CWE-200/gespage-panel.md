# Vulnerability: Gespage Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gespage-panel.yaml`)

## Description
Gespage login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gespage/webapp/login.xhtml
```

