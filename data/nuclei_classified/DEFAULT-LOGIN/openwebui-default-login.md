# Vulnerability: Open WebUI - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`openwebui-default-login.yaml`)

## Description
Detected the presence of an OpenWebUI panel with default credentials (admin@localhost/admin). Successful authentication using these default credentials allows attackers to access the admin interface and potentially perform remote code execution by defining a custom "tool".

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/auths/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email": "{{username}}", "password": "{{password}}"}
```

