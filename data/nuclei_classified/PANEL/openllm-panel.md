# Vulnerability: OpenLLM Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`openllm-panel.yaml`)

## Description
OpenLLM is an open-source platform for running and deploying LLMs in production. It is built by BentoML
and provides an OpenAI-compatible API server with a web UI for model management.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

