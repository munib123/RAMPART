# Vulnerability: Wildfly - Default Admin Login
**Classification:** WILDFLY
**Source:** Nuclei Template (`wildfly-default-login.yaml`)

## Description
Wildfly default admin login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /management HTTP/1.1
Host: {{Hostname}}
```

