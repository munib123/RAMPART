# Vulnerability: BodyBuilding.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bodybuildingcom.yaml`)

## Description
BodyBuilding.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://api.bodybuilding.com/api-proxy/bbc/get?slug={{user}}
```

