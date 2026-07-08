# Vulnerability: Apache Casbin MCP Gateway - Detection
**Classification:** TECH
**Source:** Nuclei Template (`apache-casbin-mcp-gateway-detect.yaml`)

## Description
Detects an Apache Casbin MCP Gateway server, a lightweight gateway service that instantly transforms existing MCP Servers and APIs into MCP servers with zero code changes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/health
```

