# Vulnerability: SonarQube Default Login - Detect
**Classification:** CWE-522
**Source:** Nuclei Template (`sonarqube-default-login.yaml`)

## Description
SonarQube contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/authentication/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login={{username}}&password={{password}}
```

