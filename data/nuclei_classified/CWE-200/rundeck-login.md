# Vulnerability: Rundeck Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rundeck-login.yaml`)

## Description
Rundeck login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/login
```

