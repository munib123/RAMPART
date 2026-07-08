# Vulnerability: AnythingLLM Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`anythingllm-panel.yaml`)

## Description
Detects the AnythingLLM web interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

