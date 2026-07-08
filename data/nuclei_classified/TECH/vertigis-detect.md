# Vulnerability: VertiGIS - Detect
**Classification:** TECH
**Source:** Nuclei Template (`vertigis-detect.yaml`)

## Description
VertiGIS products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
GET {{BaseURL}}/GeoManLogin.aspx
GET {{BaseURL}}/FM/GeoManLogin.aspx
GET {{BaseURL}}/GEBman/GeoManLogin.aspx
GET {{BaseURL}}/Geoportal/synserver
GET {{BaseURL}}/vertigisstudio/web/designer/locales/en/translations.json
GET {{BaseURL}}/vertigisstudio/search/designer/locales/en/translations.json
GET {{BaseURL}}/vertigisstudio/mobile/designer/locales/en/translations.json
GET {{BaseURL}}/vertigisstudio/accesscontrol/locales/en/translations.json
```

