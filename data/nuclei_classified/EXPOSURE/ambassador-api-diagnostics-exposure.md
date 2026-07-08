# Vulnerability: Ambassador API Gateway Diagnostics - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ambassador-api-diagnostics-exposure.yaml`)

## Description
Detected Ambassador API Gateway diagnostics portal, revealing service mappings, API endpoints, routing configurations, and internal cluster information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ambassador/v0/diag/
```

