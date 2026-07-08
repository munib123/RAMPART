# Vulnerability: noVNC Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`novnc-login-panel.yaml`)

## Description
noVNC login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vnc.html
GET {{BaseURL}}:6080/vnc.html
```

