# Vulnerability: Cognita Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`cognita-panel.yaml`)

## Description
Cognita is an open-source RAG framework by Truefoundry for building modular and
production-ready RAG pipelines.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

