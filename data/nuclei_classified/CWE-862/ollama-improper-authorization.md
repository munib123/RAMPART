# Vulnerability: Ollama - Improper Authorization
**Classification:** CWE-862
**Source:** Nuclei Template (`ollama-improper-authorization.yaml`)

## Description
Detected an exposed Ollama API without proper authorization, allowing unauthorized access to AI models and operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/tags
```

