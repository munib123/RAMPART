# Vulnerability: Deployment Management Interface - Exposed
**Classification:** DEPLOYMENT
**Source:** Nuclei Template (`deployment-interface-exposed.yaml`)

## Description
Deployment Management Interface is exposed. This exposure could potentially allow unauthorized access to the management interface

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

