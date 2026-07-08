# Vulnerability: Weaviate Console - Detect
**Classification:** TECH
**Source:** Nuclei Template (`weaviate-console-detect.yaml`)

## Description
Detected Weaviate Console interface. Weaviate was open-source vector database that stores data objects and vector embeddings for AI applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

