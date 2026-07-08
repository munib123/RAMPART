# Vulnerability: Webmodule Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webmodule-ee-panel.yaml`)

## Description
Webmodule login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webmodule-ee/login.seam
```

