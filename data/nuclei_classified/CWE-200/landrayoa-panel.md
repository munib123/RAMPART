# Vulnerability: Landray Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`landrayoa-panel.yaml`)

## Description
Landray login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.jsp
```

