# Vulnerability: Collibra Properties Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`collibra-properties.yaml`)

## Description
Detected exposed Collibra Properties.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/collibra.properties
GET {{BaseURL}}/app/collibra.properties
GET {{BaseURL}}/src/collibra.properties
```

