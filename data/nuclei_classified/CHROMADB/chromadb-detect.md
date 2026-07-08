# Vulnerability: ChromaDB Vector Database - Detect
**Classification:** CHROMADB
**Source:** Nuclei Template (`chromadb-detect.yaml`)

## Description
Detected ChromaDB vector database instance publicly exposed. ChromaDB is an open-source AI-native vector database. Unauthenticated instances expose stored embeddings, collections, and metadata to unauthorized access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v1/heartbeat HTTP/1.1
Host: {{Hostname}}
```

