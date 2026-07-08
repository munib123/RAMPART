# Vulnerability: Yacht - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`yacht-default-login.yaml`)

## Description
Yacht is a web interface for managing Docker containers. This template detects instances with default admin credentials (admin@yacht.local:pass), which could allow unauthorized access to the Docker environment, potentially leading to container manipulation, data exposure, or even host system compromise.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username": "{{username}}", "password": "{{password}}"}
```

