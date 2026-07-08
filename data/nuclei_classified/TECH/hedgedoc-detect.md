# Vulnerability: HedgeDoc Collaborative Editor - Detect
**Classification:** TECH
**Source:** Nuclei Template (`hedgedoc-detect.yaml`)

## Description
HedgeDoc is an open-source, collaborative markdown editor for teams to share and co-edit notes in real time. This template detects publicly reachable HedgeDoc instances by fingerprinting unique branding markers and the dedicated Hedgedoc-Version response header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

