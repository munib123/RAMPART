# Vulnerability: Google Cloud Access Token
**Classification:** GOOGLE
**Source:** Nuclei Template (`gcloud-access-token.yaml`)

## Description
Internal Google Cloud access tokens are exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/access_tokens.db
GET {{BaseURL}}/.config/gcloud/access_tokens.db
```

