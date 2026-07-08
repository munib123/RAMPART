# Vulnerability: TaskingAI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`taskingai-panel.yaml`)

## Description
TaskingAI is an open-source platform for building and deploying LLM-based agents
and AI applications with a unified API

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

