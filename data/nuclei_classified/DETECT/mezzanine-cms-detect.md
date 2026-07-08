# Vulnerability: Mezzanine CMS - Detect
**Classification:** DETECT
**Source:** Nuclei Template (`mezzanine-cms-detect.yaml`)

## Description
Detects instances of Mezzanine CMS based on unique fingerprints and identifiers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

