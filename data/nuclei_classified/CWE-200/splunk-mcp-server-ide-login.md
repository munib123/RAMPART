# Vulnerability: Splunk MCP Server IDE Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`splunk-mcp-server-ide-login.yaml`)

## Description
Splunk MCP Server IDE login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

