# Vulnerability: Apache Casbin MCP Gateway - Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`apache-casbin-mcp-gateway-default-login.yaml`)

## Description
Apache Casbin MCP Gateway server default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

