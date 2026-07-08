# Vulnerability: Mapproxy - Detect
**Classification:** TECH
**Source:** Nuclei Template (`mappproxy-detect.yaml`)

## Description
Checks for a running MapProxy instance and obtain version number. Also checks if the demo page is enabled. MapProxy is an open source proxy for geospatial data. It caches, accelerates and transforms data from existing map services and serves any desktop or web GIS client.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/demo
```

