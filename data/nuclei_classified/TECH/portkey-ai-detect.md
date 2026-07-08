# Vulnerability: Portkey AI Detection
**Classification:** TECH
**Source:** Nuclei Template (`portkey-ai-detect.yaml`)

## Description
Detected Portkey AI interface. Portkey was an AI gateway that provided observability, governance, and reliability for LLM applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

