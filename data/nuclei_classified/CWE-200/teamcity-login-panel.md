# Vulnerability: TeamCity Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teamcity-login-panel.yaml`)

## Description
TeamCity login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

