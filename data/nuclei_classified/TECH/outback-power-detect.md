# Vulnerability: OutBack Power Mate3s Gateway - Detect
**Classification:** TECH
**Source:** Nuclei Template (`outback-power-detect.yaml`)

## Description
OutBack Power Mate3s is a system hub and gateway for OutBack FX-series inverter-chargers
used in off-grid, grid-hybrid, and battery backup solar power systems.
The built-in web interface exposes system status, battery metrics, and inverter data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

