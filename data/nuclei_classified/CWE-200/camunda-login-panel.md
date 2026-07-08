# Vulnerability: Camunda Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`camunda-login-panel.yaml`)

## Description
Camunda login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/welcome/default/#!/login
GET {{BaseURL}}/camunda/app/welcome/default/#!/login
```

