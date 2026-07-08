# Vulnerability: HexStrike AI MCP Agents - Config
**Classification:** CONFIG
**Source:** Nuclei Template (`hexstrike-ai-config.yaml`)

## Description
HexStrike AI MCP Agents server config page exposure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/health
```

