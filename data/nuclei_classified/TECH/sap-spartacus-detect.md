# Vulnerability: SAP Spartacus detect
**Classification:** TECH
**Source:** Nuclei Template (`sap-spartacus-detect.yaml`)

## Description
Spartacus is a lean, Angular-based JavaScript storefront for SAP Commerce Cloud that communicates exclusively through the Commerce REST API.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

