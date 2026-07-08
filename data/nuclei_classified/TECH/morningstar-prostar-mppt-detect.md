# Vulnerability: Morningstar ProStar MPPT Solar Charge Controller - Detect
**Classification:** TECH
**Source:** Nuclei Template (`morningstar-prostar-mppt-detect.yaml`)

## Description
Morningstar ProStar MPPT is a solar charge controller with a built-in web server providing
live data monitoring for off-grid and industrial solar installations.
The exposed interface displays real-time array, battery, and load data without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

