# Vulnerability: Compal CH7465LG Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`compal-panel.yaml`)

## Description
Compal CH7465LG login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/common_page/login.html
```

