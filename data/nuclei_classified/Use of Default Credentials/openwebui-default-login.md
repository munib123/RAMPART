# Nuclei Template: Open WebUI - Default Login
**Template ID:** openwebui-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**Source:** Nuclei Template (`openwebui-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected the presence of an OpenWebUI panel with default credentials (admin@localhost/admin). Successful authentication using these default credentials allows attackers to access the admin interface and potentially perform remote code execution by defining a custom "tool".

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/auths/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email": "{{username}}", "password": "{{password}}"}
```

## References
- https://openwebui.com/
