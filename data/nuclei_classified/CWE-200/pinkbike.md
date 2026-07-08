# Vulnerability: PinkBike User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pinkbike.yaml`)

## Description
PinkBike user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.pinkbike.com/u/{{user}}/
```

