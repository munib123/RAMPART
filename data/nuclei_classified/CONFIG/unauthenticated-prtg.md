# Vulnerability: PRTG Traffic Grapher - Unauthenticated Access
**Classification:** CONFIG
**Source:** Nuclei Template (`unauthenticated-prtg.yaml`)

## Description
PRTG Traffic Grapher was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sensorlist.htm
```

