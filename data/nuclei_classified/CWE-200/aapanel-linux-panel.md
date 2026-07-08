# Vulnerability: aaPanel Linux Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aapanel-linux-panel.yaml`)

## Description
Detected aaPanel Linux management panel login interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/login
```

