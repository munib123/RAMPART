# Nuclei Template: Yacht - Default Login
**Template ID:** yacht-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`yacht-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Yacht is a web interface for managing Docker containers. This template detects instances with default admin credentials (admin@yacht.local:pass), which could allow unauthorized access to the Docker environment, potentially leading to container manipulation, data exposure, or even host system compromise.

## Steps to reproduce / Exploit Payload
```http
POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username": "{{username}}", "password": "{{password}}"}
```

## References
- https://github.com/SelfhostedPro/Yacht
- https://dev.yacht.sh/docs/Installation/Getting_Started
