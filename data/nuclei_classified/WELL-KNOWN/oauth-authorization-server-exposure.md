# Vulnerability: Well-Known OAuth Authorization Server Metadata
**Classification:** WELL-KNOWN
**Source:** Nuclei Template (`oauth-authorization-server-exposure.yaml`)

## Description
Detects OAuth 2.0 Authorization Server metadata (RFC 8414).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/oauth-authorization-server
```

