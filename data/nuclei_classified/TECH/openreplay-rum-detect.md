# Vulnerability: OpenReplay RUM - Tech Detect
**Classification:** TECH
**Source:** Nuclei Template (`openreplay-rum-detect.yaml`)

## Description
Detects OpenReplay (formerly Asayer) Session Replay & RUM SDK implementation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

