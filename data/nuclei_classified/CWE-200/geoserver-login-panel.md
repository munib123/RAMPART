# Vulnerability: GeoServer Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`geoserver-login-panel.yaml`)

## Description
GeoServer login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web
GET {{BaseURL}}/geoserver/web/
```

