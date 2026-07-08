# Vulnerability: SOPlanning - Default Login
**Classification:** SOPLANNING
**Source:** Nuclei Template (`soplanning-default-login.yaml`)

## Description
SOPlanning contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /process/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login={{username}}&password={{password}}
```

