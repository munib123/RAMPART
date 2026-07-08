# Vulnerability: Drone - Configuration Detection
**Classification:** CONFIG
**Source:** Nuclei Template (`detect-drone-config.yaml`)

## Description
Drone configuration was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.drone.yml
```

