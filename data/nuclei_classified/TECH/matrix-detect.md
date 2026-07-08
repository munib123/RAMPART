# Vulnerability: Matrix Server Detect
**Classification:** TECH
**Source:** Nuclei Template (`matrix-detect.yaml`)

## Description
Detects Matrix servers based on .well-known entries. See https://en.wikipedia.org/wiki/Matrix_(protocol)

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/matrix/server
GET {{BaseURL}}/.well-known/matrix/client
```

