# Vulnerability: OpenSpeedTest - Detect
**Classification:** TECH
**Source:** Nuclei Template (`openspeedtest-speedtest.yaml`)

## Description
Detected the exposed default page of the OpenSpeedTest service.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

