# Vulnerability: MCP SSE API Exposed - Detect
**Classification:** MCP
**Source:** Nuclei Template (`exposed-mcp-sse-server.yaml`)

## Description
Detects exposed Model Context Protocol (MCP) servers through the SSE API. MCP servers often provide administrative access to AI tools, LLM systems, or other automation infrastructure. Exposed MCP interfaces can lead to unauthorized access, information disclosure, and potential system compromise. This template detects a SSE server event stream and returns the messages endpoint which can be used to POST JSON-RPC 2.0 requests.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/sse
```

