# Vulnerability: UiPath Orchestrator Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`uipath-orchestrator-panel.yaml`)

## Description
UiPath Orchestrator login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Account/Login
```

