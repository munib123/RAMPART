# Vulnerability: ESPHome Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`esphome-dashboard.yaml`)

## Description
ESPHome Dashboard exposes the secrets like wifi password,api keys and internal logs, it also allows users to make changes through the dashboard.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

