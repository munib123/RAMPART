# Vulnerability: UISP Fiber Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`uisp-fiber-panel.yaml`)

## Description
UISP Fiber login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

