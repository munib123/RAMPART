# Vulnerability: NTFY Web - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ntfy-web-exposure.yaml`)

## Description
Publicly exposed NTFY web interface allowing unauthorized publish or subscribe access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/settings
```

