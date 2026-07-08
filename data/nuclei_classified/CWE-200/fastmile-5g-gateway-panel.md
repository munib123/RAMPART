# Vulnerability: FastMile 5G Gateway Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fastmile-5g-gateway-panel.yaml`)

## Description
FastMile 5G Gateway web interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web_whw/
GET {{BaseURL}}/web_whw/overview
```

