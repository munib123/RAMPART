# Vulnerability: HCP Anywhere - Detect
**Classification:** TECH
**Source:** Nuclei Template (`hcpanywhere-detect.yaml`)

## Description
HCP Anywhere was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/userportal/documentation/mapping.json
```

