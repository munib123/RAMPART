# Vulnerability: Indegy Sensor Setup - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`indegy-sensor-installer.yaml`)

## Description
Indegy Sensor is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/settings
```

