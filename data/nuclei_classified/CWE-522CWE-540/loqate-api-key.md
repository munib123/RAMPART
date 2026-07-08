# Vulnerability: Loqate API Key
**Classification:** CWE-522,CWE-540
**Source:** Nuclei Template (`loqate-api-key.yaml`)

## Description
Loqate API Key is leaked.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

