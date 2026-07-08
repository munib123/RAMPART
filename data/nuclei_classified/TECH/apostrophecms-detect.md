# Vulnerability: ApostropheCMS - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apostrophecms-detect.yaml`)

## Description
Detected the presence of ApostropheCMS, a full-stack content management system built on Node.js and MongoDB.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

