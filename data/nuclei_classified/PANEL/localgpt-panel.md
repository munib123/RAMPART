# Vulnerability: LocalGPT Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`localgpt-panel.yaml`)

## Description
LocalGPT is an open-source project that allows users to chat with their documents
locally using LLMs with no data leaving their device

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

