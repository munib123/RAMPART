# Vulnerability: Solar-Log - Monitoring Panel
**Classification:** PANEL
**Source:** Nuclei Template (`solar-log-panel.yaml`)

## Description
Solar-Log is a solar plant monitoring system by Solare Datensysteme GmbH (Germany)
used for PV system monitoring, yield optimisation, and fault detection. The web
interface is commonly exposed on port 80, 81, or non-standard ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

