# Vulnerability: Directus - Detect
**Classification:** TECH
**Source:** Nuclei Template (`directus-detect.yaml`)

## Description
Directus is a content manager with dynamic access API generation and transparent integration with the main databases.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

