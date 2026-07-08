# Vulnerability: Marqo Vector Search Engine - Detect
**Classification:** TECH
**Source:** Nuclei Template (`marqo-detect.yaml`)

## Description
Marqo vector search engine was detected. Marqo is an open-source tensor search and vector database that combines vector search with filtering and text/image search for AI applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

