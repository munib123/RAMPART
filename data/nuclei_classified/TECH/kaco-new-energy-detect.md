# Vulnerability: KACO New Energy Solar Inverter - Detect
**Classification:** TECH
**Source:** Nuclei Template (`kaco-new-energy-detect.yaml`)

## Description
KACO new energy is a solar inverter manufacturer. Their inverters include a built-in web server
that serves compressed HTML over HTTP for monitoring inverter status and energy production data.
Devices are commonly deployed on residential and commercial solar installations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

