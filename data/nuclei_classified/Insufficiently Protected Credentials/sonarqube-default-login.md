# Nuclei Template: SonarQube Default Login - Detect
**Template ID:** sonarqube-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`sonarqube-default-login.yaml`)

## Vulnerability Information & PoC

## Description
SonarQube contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /api/authentication/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login={{username}}&password={{password}}
```

## References
- https://docs.sonarsource.com/sonarqube/9.6/instance-administration/security/#:~:text=When%20installing%20SonarQube%2C%20a%20default,Password%3A%20admin
