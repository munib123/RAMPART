# Vulnerability: ArcGIS Enterprise Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`arcgis-panel.yaml`)

## Description
An ArcGIS instance was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/portalhelp/en/
```

