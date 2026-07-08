# Vulnerability: Janitza GridVis Energy Management - Detect
**Classification:** TECH
**Source:** Nuclei Template (`janitza-gridvis-detect.yaml`)

## Description
Janitza GridVis is an energy monitoring and management software platform by Janitza Electronics GmbH.
It provides real-time power quality analysis, energy data logging, and grid visualisation for industrial facilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/landingpage
GET {{BaseURL}}/landingpage/
```

