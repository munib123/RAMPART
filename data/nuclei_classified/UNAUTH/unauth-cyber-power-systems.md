# Vulnerability: Cyber Power Systems - Unauthenticated
**Classification:** UNAUTH
**Source:** Nuclei Template (`unauth-cyber-power-systems.yaml`)

## Description
Detects unauthenticated access to Cyber Power Systems, which could lead to unauthorized control or information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/devices
```

