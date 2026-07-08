# Vulnerability: Matrix Homeserver - Version Detection
**Classification:** TECH
**Source:** Nuclei Template (`matrix-homeserver-detect.yaml`)

## Description
Extract the Matrix homeserver name and version

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_matrix/federation/v1/version
```

