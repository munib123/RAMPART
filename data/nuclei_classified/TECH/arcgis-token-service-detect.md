# Vulnerability: ArcGIS Token Service - Detect
**Classification:** TECH
**Source:** Nuclei Template (`arcgis-token-service-detect.yaml`)

## Description
Check for the existence of the ArcGIS Token Service on an ArcGIS server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/arcgis/tokens/
```

