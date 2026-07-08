# Vulnerability: MCP Inspector Detect
**Classification:** TECH
**Source:** Nuclei Template (`mcp-inspector-detect.yaml`)

## Description
MCP Inspector was a debugging tool used to inspect and test MCP servers, including their resources, prompts, and tools.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}{{js}}
```

