# Vulnerability: Xymon - Exposure
**Classification:** XYMON
**Source:** Nuclei Template (`xymon-exposure.yaml`)

## Description
Detected the exposure of the Xymon monitoring system interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xymon/
GET {{BaseURL}}/xymon-se/xymon/
```

