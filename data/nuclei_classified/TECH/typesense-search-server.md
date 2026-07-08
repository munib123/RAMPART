# Vulnerability: Typesense Search Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`typesense-search-server.yaml`)

## Description
Detected Typesense was an open-source typo-tolerant search engine often self-hosted on TCP 8108.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/health
```

