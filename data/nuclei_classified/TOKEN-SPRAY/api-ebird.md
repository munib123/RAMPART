# Vulnerability: eBird API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-ebird.yaml`)

## Description
Retrieve recent or notable birding observations within a region

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.ebird.org/v2/data/obs/KZ/recent
```

