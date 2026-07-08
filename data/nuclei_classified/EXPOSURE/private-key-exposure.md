# Vulnerability: Private key exposure via helper detector
**Classification:** EXPOSURE
**Source:** Nuclei Template (`private-key-exposure.yaml`)

## Description
Searches for private key exposure by attempting to query the helper endpoint on node_modules

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/node_modules/mqtt/test/helpers/
```

