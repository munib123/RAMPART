# Vulnerability: eMessage Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`emessage-panel.yaml`)

## Description
eMessage login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.jsp
```

