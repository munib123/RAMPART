# Vulnerability: Credentials File Disclosure
**Classification:** GOOGLE
**Source:** Nuclei Template (`credentials-json.yaml`)

## Description
Internal secret file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/credentials.json
GET {{BaseURL}}/assets/credentials.json
```

