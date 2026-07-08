# Vulnerability: ArcGIS - Detect
**Classification:** TECH
**Source:** Nuclei Template (`arcgis-detect.yaml`)

## Description
ArcGIS products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/sharing/rest
GET {{BaseURL}}/portal/portalhelp/en/rest/
GET {{BaseURL}}/arcgis/rest/services
GET {{BaseURL}}/server/rest/services
GET {{BaseURL}}/arcgis/
```

