# Vulnerability: TimeKeeper - Default Login
**Classification:** TIMEKEEPER
**Source:** Nuclei Template (`timekeeper-default-login.yaml`)

## Description
TimeKeeper contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login?arg1={{url_encode(base64(username))}}&arg2={{url_encode(base64(password))}} HTTP/1.1
Host: {{Hostname}}
```

