# Vulnerability: LM Studio Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`lmstudio-panel.yaml`)

## Description
LM Studio is a desktop application for discovering, downloading, and running local
LLMs

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

