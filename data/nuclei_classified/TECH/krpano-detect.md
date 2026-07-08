# Vulnerability: Krpano Panorama Viewer - Detection
**Classification:** TECH
**Source:** Nuclei Template (`krpano-detect.yaml`)

## Description
Detected Krpano Panorama Viewer by identifying known Krpano-specific resources and response patterns.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/krpano.html
```

