# Vulnerability: Heatmiser Wifi Thermostat Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`heatmiser-wifi-thermostat.yaml`)

## Description
Heatmiser Wifi Thermostat panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.htm
```

