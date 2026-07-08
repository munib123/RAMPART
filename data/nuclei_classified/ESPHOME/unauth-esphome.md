# Vulnerability: ESPHome Web Server access - Unauthenticated Access
**Classification:** ESPHOME
**Source:** Nuclei Template (`unauth-esphome.yaml`)

## Description
ESPHome is a powerful smart home devices with simple YAML configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

