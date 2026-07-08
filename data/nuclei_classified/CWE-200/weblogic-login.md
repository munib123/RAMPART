# Vulnerability: Oracle WebLogic Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`weblogic-login.yaml`)

## Description
Oracle WebLogic login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console/login/LoginForm.jsp
```

