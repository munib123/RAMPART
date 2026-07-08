# Vulnerability: big-AGI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`big-agi-panel.yaml`)

## Description
big-AGI is a generative AI suite for power users, teams, and developers. It provides
an AI chat interface with support for multiple LLM providers

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

