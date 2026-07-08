# Vulnerability: Arize Phoenix - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`arize-phoenix-panel.yaml`)

## Description
Arize Phoenix is an open-source AI observability and evaluation platform for monitoring,
debugging, and evaluating LLM applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

