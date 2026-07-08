# Vulnerability: OpenStack Dashboard Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`open-stack-dashboard-login.yaml`)

## Description
OpenStack Dashboard login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard/auth/login/
GET {{BaseURL}}/horizon/auth/login/?next=/horizon/
GET {{BaseURL}}/auth/login/?next=/
```

