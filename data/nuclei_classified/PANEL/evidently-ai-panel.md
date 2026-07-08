# Vulnerability: Evidently AI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`evidently-ai-panel.yaml`)

## Description
Evidently AI is an ML/LLM observability platform for monitoring data drift and model performance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

