# Vulnerability: WSDL API - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wsdl-api.yaml`)

## Description
WSDL API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?wsdl
```

