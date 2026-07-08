# Vulnerability: SonarQube Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonarqube-login.yaml`)

## Description
SonarQube panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sessions/new
```

