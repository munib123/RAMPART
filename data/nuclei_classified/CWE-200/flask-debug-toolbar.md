# Vulnerability: Flask Debug Toolbar - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`flask-debug-toolbar.yaml`)

## Description
Detected Flask Debug Toolbar was exposed in production, potentially leaking sensitive application information, SQL queries, request data, and configuration details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

