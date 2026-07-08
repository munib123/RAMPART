# Vulnerability: OpenEnergyMonitor emonCMS - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`emoncms-panel.yaml`)

## Description
emonCMS is an open-source energy monitoring web application by OpenEnergyMonitor,
used in homes and small businesses to track electricity, gas, and temperature.
The login page is commonly exposed on port 80, 443, or 8010.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

