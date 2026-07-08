# Vulnerability: IoT vDME Simulator Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`iot-vdme-simulator.yaml`)

## Description
loT vDME Simulator panel was detected. Exposure IoT vDME Simulator panel allows anonymous access to create new Items.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

