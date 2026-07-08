# Vulnerability: Activepieces Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`activepieces-panel.yaml`)

## Description
Activepieces was detected. Activepieces was an open-source automation platform with AI and LLM integrations. Exposed instances may allow access to workflow automation configurations and connected integrations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

