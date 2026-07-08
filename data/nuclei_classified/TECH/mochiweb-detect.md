# Vulnerability: MochiWeb - Detect
**Classification:** TECH
**Source:** Nuclei Template (`mochiweb-detect.yaml`)

## Description
Detected servers using the MochiWeb framework through the Server header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

