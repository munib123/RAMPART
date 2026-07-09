# Nuclei Template: Ollama - Improper Authorization
**Template ID:** ollama-improper-authorization
**Vulnerability Class:** Missing Authorization
**Severity:** Medium
**CWE:** CWE-862
**Source:** Nuclei Template (`ollama-improper-authorization.yaml`)

## Vulnerability Information & PoC

## Description
Detected an exposed Ollama API without proper authorization, allowing unauthorized access to AI models and operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/tags
```

## References
- https://ollama.ai/
- https://github.com/ollama/ollama
