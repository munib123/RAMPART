# Vulnerability: Vanna AI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`vanna-panel.yaml`)

## Description
Vanna AI is a chat interface for text-to-SQL generation using natural language. This template detects the presence of a Vanna AI chat panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

