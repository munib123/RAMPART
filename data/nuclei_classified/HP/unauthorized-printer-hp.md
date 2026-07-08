# Vulnerability: Unauthorized HP office pro printer
**Classification:** HP
**Source:** Nuclei Template (`unauthorized-printer-hp.yaml`)

## Description
HP office pro printer web access is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/hp/device/webAccess/index.htm?content=security
```

