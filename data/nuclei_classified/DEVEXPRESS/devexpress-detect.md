# Vulnerability: DevExpress - Detect
**Classification:** DEVEXPRESS
**Source:** Nuclei Template (`devexpress-detect.yaml`)

## Description
Detect DevExpress based on the existence of its HTTP handler for serving images, scripts, and other resources to the client side.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

