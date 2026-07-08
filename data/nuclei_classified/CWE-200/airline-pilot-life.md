# Vulnerability: Airline Pilot Life User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`airline-pilot-life.yaml`)

## Description
Airline Pilot Life user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://airlinepilot.life/u/{{user}}
```

