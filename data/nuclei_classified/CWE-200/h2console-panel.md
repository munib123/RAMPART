# Vulnerability: H2 Console Web Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`h2console-panel.yaml`)

## Description
H2 Console Web login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/h2-console/login.jsp
```

