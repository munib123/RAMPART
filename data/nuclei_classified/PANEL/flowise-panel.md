# Vulnerability: Flowise Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`flowise-panel.yaml`)

## Description
Flowise panel was detected. Flowise is an open-source drag-and-drop LLM flow builderand AI agent platform. Exposed instances may reveal AI workflow configurations, API keys, and connected data sources.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

