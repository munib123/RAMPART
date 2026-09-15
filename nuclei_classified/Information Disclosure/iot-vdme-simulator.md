# Nuclei Template: IoT vDME Simulator Panel - Detect
**Template ID:** iot-vdme-simulator
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`iot-vdme-simulator.yaml`)

## Vulnerability Information & PoC

## Description
loT vDME Simulator panel was detected. Exposure IoT vDME Simulator panel allows anonymous access to create new Items.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

