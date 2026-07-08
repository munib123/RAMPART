# Vulnerability: Well-Known Nostr JSON
**Classification:** WELL-KNOWN
**Source:** Nuclei Template (`nostr-json-exposure.yaml`)

## Description
Detects Nostr public key discovery JSON.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/nostr.json
```

