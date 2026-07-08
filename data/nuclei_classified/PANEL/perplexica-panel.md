# Vulnerability: Perplexica Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`perplexica-panel.yaml`)

## Description
Perplexica is an open-source AI-powered search engine that uses SearXNG to search
the web and provides AI-generated answers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

