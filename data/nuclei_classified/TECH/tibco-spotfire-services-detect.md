# Vulnerability: TIBCO Spotfire Statistics Services - Detect
**Classification:** TECH
**Source:** Nuclei Template (`tibco-spotfire-services-detect.yaml`)

## Description
TIBCO Spotfire Statistics Services was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SplusServer/
GET {{BaseURL}}/RServer/
GET {{BaseURL}}/TERR/
GET {{BaseURL}}
```

