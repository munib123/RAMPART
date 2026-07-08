# Vulnerability: Letta Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`letta-panel.yaml`)

## Description
Letta (formerly MemGPT) is an open-source framework for building stateful LLM agents with long-term memory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

