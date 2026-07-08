# Vulnerability: Android Asset Links Configuration - Detect
**Classification:** MISC
**Source:** Nuclei Template (`assetlinks-detect.yaml`)

## Description
The .well-known/assetlinks.json file was found on the target server. This file is used by Android applications to establish verified app-to-web domain associations through the Digital Asset Links protocol.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/assetlinks.json
```

