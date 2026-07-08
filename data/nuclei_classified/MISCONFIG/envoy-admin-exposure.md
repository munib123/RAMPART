# Vulnerability: Envoy Admin Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`envoy-admin-exposure.yaml`)

## Description
Envoy Admin page exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

