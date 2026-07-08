# Vulnerability: CMSimple - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cmsimple-detect.yaml`)

## Description
Detects the presence of CMSimple, a simple content management system that requires no database (flat-file).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

