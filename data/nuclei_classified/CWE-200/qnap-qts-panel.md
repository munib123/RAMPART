# Vulnerability: QNAP Turbo NAS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`qnap-qts-panel.yaml`)

## Description
QNAP QTS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/
GET {{BaseURL}}/cgi-bin/html/login.html
```

