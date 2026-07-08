# Vulnerability: Tasmota Configuration Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tasmota-config-webui.yaml`)

## Description
Tasmota configuration is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

