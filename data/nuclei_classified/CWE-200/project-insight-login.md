# Vulnerability: Project Insight Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`project-insight-login.yaml`)

## Description
Project Insight login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

