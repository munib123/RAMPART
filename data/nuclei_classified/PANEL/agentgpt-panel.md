# Vulnerability: AgentGPT Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`agentgpt-panel.yaml`)

## Description
AgentGPT was detected. AgentGPT was a browser-based autonomous AI agent platform that allows users to create, configure and deploy AI agents directly in the browser.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

