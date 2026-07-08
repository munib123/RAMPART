# Vulnerability: ArcGIS REST Services Directory - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`arcgis-services.yaml`)

## Description
Check for the existence of the "/arcgis/rest/services" path on an ArcGIS server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/arcgis/rest/services
```

