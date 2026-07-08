# Vulnerability: Well-Known ATProto DID
**Classification:** WELL-KNOWN
**Source:** Nuclei Template (`atproto-did-exposure.yaml`)

## Description
Detects AT Protocol DID reference used by Bluesky.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/atproto-did
GET {{BaseURL}}/well-known-atproto-did
```

