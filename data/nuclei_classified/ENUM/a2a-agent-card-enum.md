# Vulnerability: Google A2A Agent Card - Enumeration
**Classification:** ENUM
**Source:** Nuclei Template (`a2a-agent-card-enum.yaml`)

## Description
Detected exposed Google Agent-to-Agent protocol agent cards. The agent-card.json file advertises an AI agent's capabilities, supported skills, authentication requirements, and endpoint URLs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/agent-card.json
GET {{BaseURL}}/.well-known/agent.json
```

