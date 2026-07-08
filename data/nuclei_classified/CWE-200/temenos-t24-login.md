# Vulnerability: Temenos Transact Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`temenos-t24-login.yaml`)

## Description
Temenos Transact login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/servlet/BrowserServlet
```

