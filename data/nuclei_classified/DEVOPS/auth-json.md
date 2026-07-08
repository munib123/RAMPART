# Vulnerability: Auth.json File - Disclosure
**Classification:** DEVOPS
**Source:** Nuclei Template (`auth-json.yaml`)

## Description
auth.json file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth.json
```

