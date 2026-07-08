# Vulnerability: HP Color LaserJet Detection
**Classification:** IOT
**Source:** Nuclei Template (`hp-color-laserjet-detect.yaml`)

## Description
HP color laserJet panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/hp/device/this.LCDispatcher
```

