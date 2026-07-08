# Vulnerability: Redfish API - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`redfish-api.yaml`)

## Description
Redfish API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/redfish/v1/
```

