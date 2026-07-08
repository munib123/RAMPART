# Vulnerability: Discover Cold Fusion cfcache.map Files
**Classification:** EXPOSURE
**Source:** Nuclei Template (`cold-fusion-cfcache-map.yaml`)

## Description
Adobe Cold Fusion cfcache.map file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cfcache.map
```

