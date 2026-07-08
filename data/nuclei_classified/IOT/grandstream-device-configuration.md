# Vulnerability: Grandstream Device Configuration
**Classification:** IOT
**Source:** Nuclei Template (`grandstream-device-configuration.yaml`)

## Description
Exposed Grandstream device configuration page detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

