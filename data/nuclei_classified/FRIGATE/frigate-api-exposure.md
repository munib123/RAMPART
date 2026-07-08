# Vulnerability: Frigate NVR - API Exposure
**Classification:** FRIGATE
**Source:** Nuclei Template (`frigate-api-exposure.yaml`)

## Description
Detected an exposed Frigate NVR API, potentially allowing unauthorized access to camera feeds, internal network configuration, and MQTT credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/config
```

