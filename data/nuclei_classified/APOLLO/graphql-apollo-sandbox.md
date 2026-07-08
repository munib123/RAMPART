# Vulnerability: Apollo Sandbox UI - Exposed
**Classification:** APOLLO
**Source:** Nuclei Template (`graphql-apollo-sandbox.yaml`)

## Description
Detects the Apollo Sandbox developer interface exposed in production environments, which could facilitate schema discovery or testing by unauthorized users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

