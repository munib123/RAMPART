# Vulnerability: FlightPath Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`flightpath-panel.yaml`)

## Description
FlightPath login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

