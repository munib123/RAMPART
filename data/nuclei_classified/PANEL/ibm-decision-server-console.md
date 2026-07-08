# Vulnerability: IBM Decision Server Console Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ibm-decision-server-console.yaml`)

## Description
IBM Decision Server Console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/res/login.jsf
```

