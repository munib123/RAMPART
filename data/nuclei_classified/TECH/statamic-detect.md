# Vulnerability: Statamic - Detect
**Classification:** TECH
**Source:** Nuclei Template (`statamic-detect.yaml`)

## Description
Statamic is the flat-first, Laravel + Git powered CMS designed for building beautiful, easy to manage websites.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

