# Vulnerability: Xweb500 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xweb500-panel.yaml`)

## Description
Xweb500 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/xweb500.cgi
```

