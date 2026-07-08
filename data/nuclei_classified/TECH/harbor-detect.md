# Vulnerability: Harbor Detect
**Classification:** TECH
**Source:** Nuclei Template (`harbor-detect.yaml`)

## Description
Harbor is an open source trusted cloud native registry project that stores, signs, and scans content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v2.0/systeminfo
```

