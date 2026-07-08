# Vulnerability: Loytec Device Info Detection
**Classification:** IOT
**Source:** Nuclei Template (`loytec-device.yaml`)

## Description
Loytec Device info panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webui/device_info/device_info
```

