# Vulnerability: Oauth Credentials Json
**Classification:** EXPOSURE
**Source:** Nuclei Template (`oauth-credentials-json.yaml`)

## Description
Oauth Credentials file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/oauth-credentials.json
```

