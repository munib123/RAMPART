# Vulnerability: Token Json File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`token-json.yaml`)

## Description
Internal token.json file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/token.json
GET {{BaseURL}}/search/token.json
```

