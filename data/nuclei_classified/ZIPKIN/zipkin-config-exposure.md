# Vulnerability: Zipkin Configuration - Exposure
**Classification:** ZIPKIN
**Source:** Nuclei Template (`zipkin-config-exposure.yaml`)

## Description
Detected the exposure of the Zipkin configuration endpoint (/config.json), which may reveal internal configuration details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.json
GET {{BaseURL}}/zipkin/config.json
```

