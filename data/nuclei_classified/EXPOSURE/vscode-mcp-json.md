# Vulnerability: Visual Studio Code MCP Configuration ("mcp.json") Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`vscode-mcp-json.yaml`)

## Description
Detected exposed VS Code MCP (Model Context Protocol) configuration files (mcp.json) which may contain sensitive information including API keys, server endpoints, authentication tokens, and tool configurations for AI assistants and language models.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mcp.json
GET {{BaseURL}}/.mcp.json
```

