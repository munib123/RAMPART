# Vulnerability: Fronius Inverter - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`fronius-inverter-panel.yaml`)

## Description
Fronius Inverter is the web interface for Fronius GEN24 and Symo series solar inverters, providing real-time monitoring, configuration, and energy management for photovoltaic systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

