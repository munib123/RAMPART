# Vulnerability: Exposed MCP JSON-RPC 2.0 API Detection
**Classification:** MCP
**Source:** Nuclei Template (`exposed-mcp-server.yaml`)

## Description
Detects exposed Machine Control Protocol (MCP) servers through JSON-RPC 2.0 API endpoints.
MCP servers often provide administrative access to AI tools, LLM systems, or other automation infrastructure.
Exposed MCP interfaces can lead to unauthorized access, information disclosure, and potential system compromise.
This template tests multiple detection methods including tools/list, rpc.discover, resources/list, and prompts/list.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}
POST {{BaseURL}}/mcp/
```

