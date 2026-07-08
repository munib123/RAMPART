# Vulnerability: Omni Commerce Connect (OCC) Rest APIs
**Classification:** TECH
**Source:** Nuclei Template (`omni-commerce-connect-detect.yaml`)

## Description
The Omni Commerce Connect (OCC) API exposes a broad set of commerce and data services. It enables you to integrate SAP Commerce functionality anywhere in your application landscape.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/occ/v2/d2OzBcy
```

