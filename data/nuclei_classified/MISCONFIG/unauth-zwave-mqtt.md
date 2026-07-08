# Vulnerability: Unauthenticated ZWave To MQTT Console
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-zwave-mqtt.yaml`)

## Description
ZWave To MQTT Console is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

