# Vulnerability: Langfuse Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`langfuse-panel.yaml`)

## Description
Langfuse panel was detected. Langfuse is an open-source LLM engineering platform for observability, evaluations, prompt management and analytics. Exposed instances may reveal LLM prompts, traces, evaluations, and connected API keys.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/public/health
```

