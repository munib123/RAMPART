# Vulnerability: HP Device Info Detection
**Classification:** IOT
**Source:** Nuclei Template (`hp-device-info-detect.yaml`)

## Description
Internal info is disclosed to external users in HP Device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hp/device/DeviceInformation/View
```

