# Vulnerability: FleetCart Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`fleetcart-installer.yaml`)

## Description
Detects exposed FleetCart setup installation pages which could allow unauthorized access or information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

