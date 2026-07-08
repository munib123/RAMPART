# Vulnerability: ArcGIS Exposed REST API documentation
**Classification:** CWE-200
**Source:** Nuclei Template (`arcgis-rest-api.yaml`)

## Description
ArcGIS REST API documentation was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/server/sdk/rest/index.html
```

