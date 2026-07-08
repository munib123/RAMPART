# Vulnerability: ChromaDB Installer - Detected
**Classification:** ADMIN
**Source:** Nuclei Template (`chromadb-installer.yaml`)

## Description
Detects the presence of the ChromaDB admin interface.The endpoint reveals connection details and authentication type.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

